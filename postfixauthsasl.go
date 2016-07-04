// Copyright © 2016 Jörg Kost, joerg.kost@gmx.com
// License: https://creativecommons.org/licenses/by-nc-sa/4.0/

package main

import (
	"bufio"
	"database/sql"
	_ "database/sql/driver"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

/* Defaults, allow mailCounter in durationCounter */
var hostPortSendmail = flag.String("bindSendmail", "localhost:9443", "ip and port for the listening socket for sendmail auth user requests")
var hostPortPolicy = flag.String("bindPolicy", "localhost:8443", "ip and port for the listening socket for policy-connections")
var mailCounter = flag.Int("c", 10, "allowed numbers of mail during duration")
var durationCounter = flag.Int64("t", 60, "duration for the allowed number of mails")
var RunSendmail = flag.Bool("rm", false, "Run Sendmail policy")
var RunSASLpolicy = flag.Bool("rs", false, "Run SASL policyd")

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

/* sMC = staticMailCounters read by sql driver */
var sMC = make(map[string]int)

func handleUserLimit(userHost string) string {
	var personalMailLimit int
	mu.Lock()
	newSlice := make([]time.Time, 0, 15)

	for i := 0; i < len(uMC[userHost]); i++ {
		if int64(time.Since(uMC[userHost][i])/time.Second) < *durationCounter {
			newSlice = append(newSlice, uMC[userHost][i])
		}
	}
	uMC[userHost] = newSlice
	mu.Unlock()

	fmt.Println(userHost)
	personalMailLimit = *mailCounter
	_, ok  := sMC[userHost]
	if ok == true {
		personalMailLimit = sMC[userHost]
		fmt.Println("found user " + userHost)
		fmt.Printf("Setting limit to %d\n", personalMailLimit)
	}

	if len(uMC[userHost]) > personalMailLimit {
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

func listenPort(wg *sync.WaitGroup, Handler func(net.Conn), AddrPort string) {
	defer wg.Done()

	ln, err := net.Listen("tcp", AddrPort)
	if err != nil {
		log.Fatal(err)
	}

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

func scanUserLimits() {
	/* open connection to db */
	db, err := sql.Open("sqlite3", "./ratepolicy.db")
	checkErr(err)

	rows, err := db.Query("SELECT sasl_username, sasl_limit FROM rate_sasl_user_limits")
	checkErr(err)
	for rows.Next() {
		var sasl_username string
		var sasl_limit int
		err = rows.Scan(&sasl_username, &sasl_limit)
		checkErr(err)
		sMC[sasl_username] = sasl_limit
	}
	db.Close()
}

func main() {
	runtime.GOMAXPROCS(2)
	var wg sync.WaitGroup

	flag.Parse()
	scanUserLimits()

	/* Create send mail and policy-connector  */
	if *RunSendmail == true {
		go listenPort(&wg, handleSendmailConnection, *hostPortSendmail)
		wg.Add(1)
	}
	if *RunSASLpolicy == true {
		go listenPort(&wg, handlePolicyConnection, *hostPortPolicy)
		wg.Add(1)
	}

	/* Wait for both threads to end */
	wg.Wait()
	os.Exit(0)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
