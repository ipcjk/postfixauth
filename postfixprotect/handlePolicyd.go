package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

func handlePolicyConnection(pConn net.Conn) {
	var saslUsername string
	var policySender string
	var thisIsEnd = make(chan struct{})

	sawRequest := false

	defer pConn.Close()

	/* We need start a timeout for hanging policy requests
	 * timeoutPolicyCheck will set a limit for the WHOLE transaction (db-lookup,
	 * blacklistCheck ... , so please be gentle!
	 */

	go func() {
		select {
		case <-thisIsEnd:
			return
		case <-time.After(time.Second * time.Duration(*timeoutPolicyCheck)):
			fmt.Fprint(pConn, postfixTimeout)
			pConn.Close()
			thisIsEnd <- struct{}{}
		}
	}()

	scanner := bufio.NewScanner(pConn)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), postfixPolicyRequest) {
			sawRequest = true
		} else if strings.HasPrefix(scanner.Text(), postfixPolicySender) {
			policySender = strings.Trim(scanner.Text(), postfixPolicySender)
		} else if strings.HasPrefix(scanner.Text(), postfixPolicyUsername) {
			saslUsername = strings.Trim(scanner.Text(), postfixPolicyUsername)
		} else if utf8.RuneCountInString(scanner.Text()) == 0 {
			break
		}
	}

	if scanner.Err() != nil {
		// fmt.Println("Timeout receiving data: ", scanner.Err())
		goto closeConnection
	}

	/* If we did not see the request pattern or no sasl_username, we dont need to
	 * waste any more cpu time
	 */
	if sawRequest == false || utf8.RuneCountInString(saslUsername) == 0 {
		goto returnDefaultThenHandleNextRequest
	}

	/* If we saw a sender address, check this for blacklisting */
	if utf8.RuneCountInString(policySender) > 0 && challengeSender(policySender) == true {
		fmt.Fprint(pConn, postfixErrFmt)
		goto handleNextRequest
	}

	/* Everything fine till here? Then validate the limit */
	fmt.Fprint(pConn, handleUserLimit(saslUsername))
	goto handleNextRequest

returnDefaultThenHandleNextRequest:
	fmt.Fprint(pConn, postfixDefaultFmt)

handleNextRequest:
	handlePolicyConnection(pConn)

closeConnection:
	thisIsEnd <- struct{}{}
	return
}
