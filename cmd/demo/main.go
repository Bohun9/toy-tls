package main

import (
	"flag"
	"fmt"
	"github.com/Bohun9/toy-tls/tls"
)

func main() {
	hostname := flag.String("host", "localhost", "server hostname to connect to")
	port := flag.Int("port", 443, "server port")
	verbose := flag.Bool("v", false, "enable verbose TLS logging")
	flag.Parse()

	conn, err := tls.Dial("tcp", *hostname, *port, *verbose)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	request := fmt.Appendf(nil, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", *hostname)
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
