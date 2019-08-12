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
	var saslUsername, policySender string
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
			policySender = strings.TrimPrefix(strings.ToLower(scanner.Text()), postfixPolicySender)
		} else if strings.HasPrefix(scanner.Text(), postfixPolicyUsername) {
			saslUsername = strings.TrimPrefix(scanner.Text(), postfixPolicyUsername)
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
	if utf8.RuneCountInString(policySender) > 0 && challengeSender(policySender) != nil {
		fmt.Fprint(pConn, postfixPolicyBlackListReject)
		goto closeConnection
	}

	/* Everything fine till here? Then validate the limit */
	if !isUserInLimit(saslUsername, *durationCounter, *mailCounterPolicyd) {
		fmt.Fprint(pConn, postfixPolicyReject)
		goto closeConnection
	}

returnDefaultThenHandleNextRequest:
	fmt.Fprint(pConn, postfixPolicyDefaultFmt)

closeConnection:
	thisIsEnd <- struct{}{}
	return
}
