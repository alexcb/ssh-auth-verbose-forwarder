package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/alexcb/ssh-auth-verbose-forwarder/proxy"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	sockPath := "/tmp/ssh-forward.sock"
	socket, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(sockPath)

	agentSockPath := os.Getenv("SSH_AUTH_SOCK")
	fmt.Printf("listening on %s; proxying calls to %s\n", sockPath, agentSockPath)
	for {
		// Accept an incoming connection.
		conn, err := socket.Accept()
		if err != nil {
			log.Fatal(err)
		}

		// Handle the connection in a separate goroutine.
		go func(conn net.Conn) {
			defer conn.Close()

			agentSock, err := net.Dial("unix", agentSockPath)
			if err != nil {
				log.Fatal(err)
			}
			sshAgent := agent.NewClient(agentSock)

			ap := proxy.NewAgent(sshAgent)
			err = agent.ServeAgent(ap, conn)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
		}(conn)
	}

}
