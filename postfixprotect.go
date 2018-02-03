// Copyright © 2018 Jörg Kost, joerg.kost@gmx.com
// License: https://creativecommons.org/licenses/by-nc-sa/4.0/

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gops/agent"
)

/* Some globals */
var debug = flag.Bool("debug", false, "Debug outputs")
var listenPortSendmail = flag.String("bindSendmail", "localhost:8443", "ip and port for the listening socket for sendmail auth user requests")
var listenPortPolicy = flag.String("bindPolicy", "localhost:9443", "ip and port for the listening socket for policy-connections")
var runSendmailProtect = flag.Bool("sendmailprotect", false, "Run Sendmail policyd")
var runSASLpolicyd = flag.Bool("saslprotect", true, "Run SASL policyd")
var durationCounter = flag.Int64("duration", 60, "default duration for mailCounters")
var mailCounter = flag.Int("mailcounter", 25, "default mailcounter till blocking in duration")
var timeoutPolicyCheck = flag.Int("timeout", 30, "timeout waiting for handle the client connection")

/* Postfix strings */
var postfixOkFmt = "200 OK (%d)\n"
var postfixErrFmt = "500 Limit reached\n"
var postfixTimeout = "451 Timeout client\n"
var postfixDefaultFmt = "DUNNO default\n"
var postfixPolicyUsername = "sasl_username="
var postfixPolicyRequest = "request="
var postfixPolicySender = "sender="

/* Mutex for map-access */
var mu sync.Mutex

/* uMC = userMailCounter */
var currentMailByUser = make(map[string][]time.Time)

/* sMC = staticMailCounters read by txt file */
var limitMailByUser = make(map[string]int)

/* blacklisted senderDomains = blacklistDomains read by txt file
to be implemented
*/
var blacklistDomains = make(map[string]bool)

/* to be implemented */
func challengeSender(sender string) bool {
	return false
}

func listenPort(wg *sync.WaitGroup, Handler func(net.Conn), AddrPort string) {
	defer wg.Done()

	ln, err := net.Listen("tcp", AddrPort)
	checkErr(err)

	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Could not accept client", err.Error())
		} else {
			go Handler(conn)
		}
	}
}

func main() {
	var wg sync.WaitGroup

	flag.Parse()

	if err := agent.Listen(agent.Options{}); err != nil {
		log.Fatal(err)
	}

	/* Load our txt files */
	loadBlacklist()
	loadLimits()

	if *runSASLpolicyd == true {
		go listenPort(&wg, handlePolicyConnection, *listenPortPolicy)
		wg.Add(1)
	}

	if *runSendmailProtect == true {
		go listenPort(&wg, handleSendmailConnection, *listenPortSendmail)
		wg.Add(1)
	}

	wg.Wait()
	os.Exit(0)
}

func loadLimits() {
	file, err := os.Open("limits.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}

		limit, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		limitMailByUser[fields[0]] = limit
	}

}

func loadBlacklist() {
	file, err := os.Open("blacklist.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blacklistDomains[scanner.Text()] = true
	}
}

func checkErr(err error) {
	if err != nil {
		log.Println(err)
	}
}
