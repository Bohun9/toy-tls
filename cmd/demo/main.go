package main

import (
	"fmt"
	"github.com/Bohun9/toy-tls/tls"
)

const hostname = "www.example.com"

func main() {
	conn, err := tls.Dial("tcp", hostname, 443)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	request := fmt.Appendf(nil, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", hostname)
	if _, err := conn.Write(request); err != nil {
		panic(err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(response[:n]))
}
