// Copyright © 2016 Jörg Kost, joerg.kost@gmx.com
// License: https://creativecommons.org/licenses/by-nc-sa/4.0/

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

/* Defaults, allow mailCounter in durationCounter */
var hostPort = flag.String("bind", "localhost:8443", "ip and port for the listening socket, so postfix can connect")
var mailCounter = flag.Int("c", 10, "allowed numbers of mail during duration")
var durationCounter = flag.Int64("t", 60, "duration for the allowed number of mails")

/* String Formats */
var postfixOkFmt string = "200 OK (%d)\n"
var postfixErrFmt string = "500 Limit reached\n"

/* Mutex for map-access */
var mu sync.Mutex

/* uMC = userMailCounter */
var uMC = make(map[string][]time.Time)

func handleConnection(pConn net.Conn)  {
	defer pConn.Close()

	user, err := bufio.NewReader(pConn).ReadString('\n')
	if err != nil {
		fmt.Println("Cant read user", err.Error())
		return
	}

	user = strings.TrimSuffix(user, "\n")
	user = strings.TrimPrefix(user, "get ");

	if utf8.RuneCountInString(user) == 0  {
		fmt.Fprint(pConn, postfixErrFmt)
		return
	}

	mu.Lock()
	host, _, err := net.SplitHostPort(pConn.RemoteAddr().String())
	if err != nil {
		fmt.Println("Cant read ip and port", err.Error())
		return
	}

	userHost := user + "@" + host
	newSlice := make([]time.Time, 0, 15)

	for i := 0; i < len(uMC[userHost]); i++ {
		if int64(time.Since(uMC[userHost][i])/time.Second) < *durationCounter {
			newSlice = append(newSlice, uMC[userHost][i])
		}
	}
	uMC[userHost] = newSlice
	mu.Unlock()

	if len(uMC[userHost]) > *mailCounter {
		fmt.Fprint(pConn, postfixErrFmt)
	} else {
		fmt.Fprintf(pConn, postfixOkFmt, len(uMC[userHost]))
		uMC[userHost] = append(uMC[userHost], time.Now())
	}

	return
}

func main() {
	flag.Parse()

	ln, err := net.Listen("tcp", *hostPort)
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Could not accept client", err.Error())
		} else {
			go handleConnection(conn)
		}
	}

	os.Exit(0)
}
