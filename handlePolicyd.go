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
	var saslUsername, policySender, policyRecipient string
	var thisIsEnd = make(chan struct{})
	var allowed bool
	var personalLimit, personalDuration, lenUserLimit int

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
		} else if strings.HasPrefix(scanner.Text(), postfixPolicyRecipient) {
			policyRecipient = strings.TrimPrefix(strings.ToLower(scanner.Text()), postfixPolicyRecipient)
		} else if utf8.RuneCountInString(scanner.Text()) == 0 {
			break
		}
	}

	if scanner.Err() != nil {
		// fmt.Println("Timeout receiving data: ", scanner.Err())
		goto closeConnection
	}

	/* did we a policy request? else bail out */
	if sawRequest == false {
		goto returnDefaultThenHandleNextRequest
	}

	/* greylisting enabled? */
	if *greyListing && utf8.RuneCountInString(saslUsername) == 0 {
		allowed = isSenderGreyListed(policySender, policyRecipient)
		if !allowed {
			fmt.Fprint(pConn, postfixGreyListing)
			goto closeConnection
		}
		goto returnDefaultThenHandleNextRequest
	}

	/* SASL user? */
	if utf8.RuneCountInString(saslUsername) == 0 {
		goto returnDefaultThenHandleNextRequest
	}

	/* If we saw a sender address, check this for blacklisting */
	if utf8.RuneCountInString(policySender) > 0 && challengeSender(policySender) != nil {
		fmt.Fprint(pConn, postfixPolicyBlackListReject)
		goto closeConnection
	}

	/* If we saw a sasl_username, check this for blacklisting */
	if utf8.RuneCountInString(saslUsername) > 0 && challengeSender(saslUsername) != nil {
		fmt.Fprint(pConn, postfixPolicyBlackListReject)
		goto closeConnection
	}

	/* Everything fine till here? Then validate the limit */
	allowed, personalLimit, personalDuration, lenUserLimit = isUserInLimit(saslUsername, *durationCounter, *mailCounterPolicyd)
	if !allowed {
		fmt.Fprintf(pConn, postfixPolicyReject, personalLimit, personalDuration, lenUserLimit)
		goto closeConnection
	}

returnDefaultThenHandleNextRequest:
	fmt.Fprint(pConn, postfixPolicyDefaultFmt)

closeConnection:
	thisIsEnd <- struct{}{}
	return
}

