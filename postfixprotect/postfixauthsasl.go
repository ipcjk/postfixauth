// Copyright © 2016 Jörg Kost, joerg.kost@gmx.com
// License: https://creativecommons.org/licenses/by-nc-sa/4.0/

package main

import (
	"bufio"
	"database/sql"
	_ "database/sql/driver"
	"flag"
	"fmt"
	"github.com/go-ini/ini"
	_ "github.com/mattn/go-sqlite3"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

/* Flags and argv parser */
var DEBUG = flag.Bool("debug", false, "Debug outputs")
var configFile = flag.String("config", "postfixauthsasl.ini", "path to our configuration")
var listenPortSendmail = flag.String("bindSendmail", "localhost:9443", "ip and port for the listening socket for sendmail auth user requests")
var listenPortPolicy = flag.String("bindPolicy", "localhost:8443", "ip and port for the listening socket for policy-connections")
var RunSendmailProtect = flag.Bool("sendmailprotect", false, "Run Sendmail policyd")
var RunSASLpolicyd = flag.Bool("saslprotect", false, "Run SASL policyd")

/* Globals */
var mailCounter int
var durationCounter int64

/* Postfix strings */
var postfixOkFmt string = "200 OK (%d)\n"
var postfixErrFmt string = "500 Limit reached\n"
var postfixDefaultFmt string = "DUNNO default\n"
var postfixPolicyUsername = "sasl_username="
var postfixPolicyRequest = "request="

/* Mutex for map-access */
var mu sync.Mutex

/* uMC = userMailCounter */
var uMC = make(map[string][]time.Time)

/* sMC = staticMailCounters read by sql driver */
var sMC = make(map[string]int)

/* blacklisted senderDomains = blacklistDomains read by sql driver */
var bMC = make(map[string]bool)

func handleUserLimit(userHost string) string {
	var personalMailLimit int
	mu.Lock()
	newSlice := make([]time.Time, 0, 15)

	for i := 0; i < len(uMC[userHost]); i++ {
		if int64(time.Since(uMC[userHost][i])/time.Second) < durationCounter {
			newSlice = append(newSlice, uMC[userHost][i])
		}
	}
	uMC[userHost] = newSlice
	mu.Unlock()

	personalMailLimit = mailCounter
	_, ok := sMC[userHost]
	if ok == true {
		personalMailLimit = sMC[userHost]
		if *DEBUG == true {
			fmt.Println("found user " + userHost)
			fmt.Printf("Setting limit to %d\n", personalMailLimit)
		}
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
		} else if strings.HasPrefix(scanner.Text(), postfixPolicyUsername) {
			sasl_username = strings.Trim(scanner.Text(), postfixPolicyUsername)
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

func load_blacklist(section map[string]string) {
	db, err := sql.Open(section["driver"], section["dsn"])
	defer db.Close()

	checkErr(err)

	rows, err := db.Query(section["q"])
	checkErr(err)
	for rows.Next() {
		var domain string
		err = rows.Scan(&domain)
		checkErr(err)
		bMC[domain] = true
	}

	if *DEBUG == true {
		fmt.Println("Loaded blacklisted domains")
		fmt.Println(bMC)
	}
}

func load_userlimits(section map[string]string) {
	db, err := sql.Open(section["driver"], section["dsn"])
	defer db.Close()

	checkErr(err)

	rows, err := db.Query(section["q"])
	checkErr(err)
	for rows.Next() {
		var sasl_username string
		var sasl_limit int
		err = rows.Scan(&sasl_username, &sasl_limit)
		checkErr(err)
		sMC[sasl_username] = sasl_limit
	}

	if *DEBUG == true {
		fmt.Println("Loaded user limits")
		fmt.Println(sMC)
	}

}

func load_config() {
	/* Load configuration file */
	cfg, err := ini.Load(*configFile)
	checkErr(err)

	durationCounter = cfg.Section("general").Key("duration").MustInt64(60)
	mailCounter = cfg.Section("general").Key("mailCounter").MustInt(10)
	*DEBUG = cfg.Section("general").Key("debug").MustBool(true)

	/* connect db and load blacklist database if necessary */
	hash := cfg.Section("blacklist_db").KeysHash()
	if val, ok := hash["enabled"]; ok {
		if val == "1" {
			load_blacklist(hash)
		}
	}

	/* connect db and load blacklist database if necessary */
	hash = cfg.Section("userlimit_db").KeysHash()
	if val, ok := hash["enabled"]; ok {
		if val == "1" {
			load_userlimits(hash)
		}
	}

	if *DEBUG == true {
		fmt.Printf("Loaded Duration %d\n", durationCounter)
		fmt.Printf("Loaded Max Mails per Duration %d\n", mailCounter)
	}

}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	load_config()
}

func main() {
	var wg sync.WaitGroup

	/* Create send mail and policy-connector  */
	if *RunSendmailProtect == true {
		go listenPort(&wg, handleSendmailConnection, *listenPortSendmail)
		wg.Add(1)
	}
	if *RunSASLpolicyd == true {
		go listenPort(&wg, handlePolicyConnection, *listenPortPolicy)
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
