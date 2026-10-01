package socks5

import (
	"errors"
	"fmt"
	"io"

	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// NoAuth          = uint8(0)
	// noAcceptable    = uint8(255)
	// UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

type AuthMethod uint8

const (
	NoAuth       = AuthMethod(0)
	UserPassAuth = AuthMethod(2)
	noAcceptable = AuthMethod(255)
)

func (m AuthMethod) String() string {
	switch m {
	case NoAuth:
		return "no_auth"

	case UserPassAuth:
		return "user_pass_auth"

	default:
		return "no_acceptable"
	}
}

func (m AuthMethod) Code() uint8 {
	return uint8(m)
}

var (
	UserAuthFailed  = errors.New("User authentication failed")
	NoSupportedAuth = fmt.Errorf("No supported authentication mechanism")
)

// A Request encapsulates authentication state provided
// during negotiation
type AuthContext struct {
	// Provided auth method
	Method uint8
	// Payload provided during negotiation.
	// Keys depend on the used auth method.
	// For UserPassauth contains Username
	Payload map[string]string
}

func (a AuthContext) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint8("method", a.Method)
	enc.AddObject("payload", zapcore.ObjectMarshalerFunc(func(oe zapcore.ObjectEncoder) error {
		for k, v := range a.Payload {
			oe.AddString(k, v)
		}
		return nil
	}))
	return nil
}

type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer, logger *zap.Logger) (*AuthContext, error)
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth.Code()
}

func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer, logger *zap.Logger) (*AuthContext, error) {
	_, err := writer.Write([]byte{socks5Version, NoAuth.Code()})
	return &AuthContext{NoAuth.Code(), nil}, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth.Code()
}

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, logger *zap.Logger) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{socks5Version, UserPassAuth.Code()}); err != nil {
		return nil, err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return nil, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return nil, err
	}

	// Verify the password
	if a.Credentials.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
		return nil, UserAuthFailed
	}

	// Done
	return &AuthContext{UserPassAuth.Code(), map[string]string{"Username": string(user)}}, nil
}

// authenticate is used to handle connection authentication
func (s *Server) authenticate(ctx context.Context, conn io.Writer, bufConn io.Reader) (*AuthContext, error) {
	fields := make([]zap.Field, 2)

	if remoteIP := ctx.Value("remote_ip"); remoteIP != nil {
		if v, ok := remoteIP.(string); ok {
			fields = append(fields, zap.String("remote_ip", v))
		}
	}

	if requestID := ctx.Value("request_id"); requestID != nil {
		if v, ok := requestID.(string); ok {
			fields = append(fields, zap.String("request_id", v))
		}
	}

	l := s.config.Logger.With(fields...)

	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		l.Error("auth select", zap.Error(err))
		return nil, fmt.Errorf("Failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			l.Info("auth select", zap.Uint8("method_code", method), zap.String("method_name", AuthMethod(method).String()))
			return cator.Authenticate(bufConn, conn, l)
		}
	}

	// No usable method found
	// return nil, noAcceptableAuth(conn)
	err = noAcceptableAuth(conn)
	l.Error("auth select", zap.Error(err))
	return nil, err
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{socks5Version, noAcceptable.Code()})
	return NoSupportedAuth
}

// readMethods is used to read the number of methods
// and proceeding auth methods
func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}
