package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

func handleSendmailConnection(pConn net.Conn) {
	defer pConn.Close()

	host, _, err := net.SplitHostPort(pConn.RemoteAddr().String())
	if err != nil {
		fmt.Println("Cant read ip and port", err.Error())
		return
	}

	user, err := bufio.NewReader(pConn).ReadString('\n')
	if err != nil {
		fmt.Println("Cant read user", err.Error())
		return
	}

	user = strings.TrimSuffix(user, "\n")
	user = strings.TrimPrefix(user, "get ")

	if utf8.RuneCountInString(user) == 0 {
		fmt.Fprint(pConn, postfixErrFmt)
		return
	}

	/* Everything fine till here? Then validate the limit */
	if !isUserInLimit(user + "@" + host) {
		fmt.Fprint(pConn, postfixErrFmt)
		return
	}

	fmt.Fprint(pConn, postfixOkFmt)
	return

}
