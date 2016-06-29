// Copyright © 2016 Jörg Kost, joerg.kost@gmx.com
// License: https://creativecommons.org/licenses/by-nc-sa/4.0/

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"os"
)

/* Defaults, allow mailCounter in durationCounter */
var hostPortSendmail = flag.String("bindSendmail", "localhost:9443", "ip and port for the listening socket for sendmail auth user requests")
var hostPortPolicy = flag.String("bindPolicy", "localhost:8443", "ip and port for the listening socket for policy-connections")
var mailCounter = flag.Int("c", 10, "allowed numbers of mail during duration")
var durationCounter = flag.Int64("t", 60, "duration for the allowed number of mails")

/* String Formats */
var postfixOkFmt string = "200 OK (%d)\n"
var postfixErrFmt string = "500 Limit reached\n"
var postfixDefaultFmt string = "DUNNO default\n"

/* policyd-search */
var postfixSaslUsername = "sasl_username="
var postfixPolicyRequest = "request="

/* Mutex for map-access */
var mu sync.Mutex

/* uMC = userMailCounter */
var uMC = make(map[string][]time.Time)

func handleUserLimit(userHost string) string {
	mu.Lock()
	newSlice := make([]time.Time, 0, 15)

	for i := 0; i < len(uMC[userHost]); i++ {
		if int64(time.Since(uMC[userHost][i])/time.Second) < *durationCounter {
			newSlice = append(newSlice, uMC[userHost][i])
		}
	}
	uMC[userHost] = newSlice
	mu.Unlock()

	if len(uMC[userHost]) > *mailCounter {
		return fmt.Sprintf(postfixErrFmt)
	} else {
		uMC[userHost] = append(uMC[userHost], time.Now())
		return fmt.Sprintf(postfixOkFmt, len(uMC[userHost]))
	}
}

func handlePolicyConnection(pConn net.Conn) {
	var sasl_username string
	sawRequest := false

	defer pConn.Close()

	host, _, err := net.SplitHostPort(pConn.RemoteAddr().String())
	if err != nil {
		fmt.Println("Cant read ip and port", err.Error())
		return
	}

	scanner := bufio.NewScanner(pConn)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), postfixPolicyRequest) {
			sawRequest = true
			continue
		} else if strings.HasPrefix(scanner.Text(), postfixSaslUsername) {
			sasl_username = strings.Trim(scanner.Text(), postfixSaslUsername)
		} else if utf8.RuneCountInString(scanner.Text()) == 0 {
			break
		}
	}

	if sawRequest == true && utf8.RuneCountInString(sasl_username) > 0 {
		fmt.Fprint(pConn, handleUserLimit(sasl_username+"@"+host))
		return
	}

	fmt.Fprint(pConn, postfixDefaultFmt)
	return
}

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

	fmt.Fprint(pConn, handleUserLimit(user+"@"+host))
	return

}

func listenSendMail(wg *sync.WaitGroup) {
	ln, err := net.Listen("tcp", *hostPortSendmail)
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Could not accept client", err.Error())
		} else {
			go handleSendmailConnection(conn)
		}
	}
	wg.Done()
}

func listenPolicy(wg *sync.WaitGroup) {
	ln, err := net.Listen("tcp", *hostPortPolicy)
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Could not accept client", err.Error())
		} else {
			go handlePolicyConnection(conn)
		}
	}
	wg.Done()
}

func main() {
	flag.Parse()
	var wg sync.WaitGroup
	wg.Add(2)

	/* Create sendmail and policy-connector  */
	go listenPolicy(&wg)
	go listenSendMail(&wg)

	wg.Wait();
	//select {}
	os.Exit(0)
}
