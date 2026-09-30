package main

import "github.com/jitlogan/go-socks5"

func main() {
	conf := &socks5.Config{
		Credentials: socks5.StaticCredentials{
			"jora":   "secret123",
			"grisha": "jopa123",
		},
	}

	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	server.ListenAndServe("tcp", ":8080")
}
