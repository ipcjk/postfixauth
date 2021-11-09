package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

func handleSendmailConnection(pConn net.Conn) {
	var allowed bool
	var personalLimit, personalDuration, lenUserLimit int

	defer pConn.Close()

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
	allowed, personalLimit, personalDuration, lenUserLimit = isUserInLimit(user, *durationCounter, *mailCounterSendmail)
	if !allowed {
		fmt.Fprintf(pConn, postfixPolicyReject, personalLimit, personalDuration, lenUserLimit)
		return
	}

	fmt.Fprint(pConn, postfixOkFmt)
	return

}
