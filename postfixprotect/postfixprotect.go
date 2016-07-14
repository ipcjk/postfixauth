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
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

/* Flags and argv parser */
var DEBUG = flag.Bool("debug", false, "Debug outputs")
var configFile = flag.String("config", "postfixprotect.ini", "path to our configuration")
var listenPortSendmail = flag.String("bindSendmail", "localhost:8443", "ip and port for the listening socket for sendmail auth user requests")
var listenPortPolicy = flag.String("bindPolicy", "localhost:9443", "ip and port for the listening socket for policy-connections")
var RunSendmailProtect = flag.Bool("sendmailprotect", false, "Run Sendmail policyd")
var RunSASLpolicyd = flag.Bool("saslprotect", false, "Run SASL policyd")

/* Globals */
var mailCounter int
var durationCounter int64
var timeoutPolicyCheck int

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

/* sMC = staticMailCounters read by sql driver */
var limitMailByUser = make(map[string]int)

/* blacklisted senderDomains = blacklistDomains read by sql driver */
var blacklistDomains = make(map[string]bool)

/* to be implemented */
func challengeSender(sender string) bool {
	return false
}

func handleUserLimit(userHost string) string {
	var personalMailLimit int
	mu.Lock()
	newSlice := make([]time.Time, 0, 15)

	for i := 0; i < len(currentMailByUser[userHost]); i++ {
		if int64(time.Since(currentMailByUser[userHost][i])/time.Second) < durationCounter {
			newSlice = append(newSlice, currentMailByUser[userHost][i])
		}
	}
	currentMailByUser[userHost] = newSlice
	mu.Unlock()

	personalMailLimit = mailCounter
	_, ok := limitMailByUser[userHost]
	if ok == true {
		personalMailLimit = limitMailByUser[userHost]
		if *DEBUG == true {
			fmt.Printf("(%s)->limit(%d)\n", userHost, personalMailLimit)
		}
	}

	if len(currentMailByUser[userHost]) >= personalMailLimit {
		return fmt.Sprintf(postfixErrFmt)
	} else {
		currentMailByUser[userHost] = append(currentMailByUser[userHost], time.Now())
		return fmt.Sprintf(postfixOkFmt, len(currentMailByUser[userHost]))
	}
}

func handlePolicyConnection(pConn net.Conn) {
	var sasl_username string
	var policy_sender string
	var thisIsEnd = make(chan struct{})

	sawRequest := false

	defer pConn.Close()

	host, _, err := net.SplitHostPort(pConn.RemoteAddr().String())
	if err != nil {
		fmt.Println("Cant read ip and port", err.Error())
		return
	}

	/* We need start a timeout for hanging policy requets
	 * timeoutPolicyCheck will set a limit for the WHOLE transaction (db-lookup,
	 * blacklistCheck ... , so please be gentle!
	 */

	go func() {
		select {
		case <-thisIsEnd:
			return
		case <-time.After(time.Second * time.Duration(timeoutPolicyCheck)):
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
			policy_sender = strings.Trim(scanner.Text(), postfixPolicySender)
		} else if strings.HasPrefix(scanner.Text(), postfixPolicyUsername) {
			sasl_username = strings.Trim(scanner.Text(), postfixPolicyUsername)
		} else if utf8.RuneCountInString(scanner.Text()) == 0 {
			break
		}
	}

	if scanner.Err() != nil {
		fmt.Println("Timeout receiving data: ", scanner.Err())
		goto cleanup
	}

	/* If we did not see the request pattern or no sasl_username, we dont need to
	 * waste any more cpu time
	 */
	if sawRequest == false || utf8.RuneCountInString(sasl_username) == 0 {
		goto returnDefault
	}

	/* If we saw a sender address, check this for blacklisting */
	if utf8.RuneCountInString(policy_sender) > 0 && challengeSender(policy_sender) == true {
		fmt.Fprint(pConn, postfixErrFmt)
		goto cleanup
	}

	/* Everything fine till here? Then validate the limit */
	fmt.Fprint(pConn, handleUserLimit(sasl_username+"@"+host))
	goto cleanup

returnDefault:
	fmt.Fprint(pConn, postfixDefaultFmt)

cleanup:
	thisIsEnd <- struct{}{}
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

func read_db_callback(dbconnection map[string]string, parseSQL func(sql.Rows)) {
	db, err := sql.Open(dbconnection["driver"], dbconnection["dsn"])
	defer db.Close()
	rows, err := db.Query(dbconnection["q"])
	checkErr(err)
	parseSQL(*rows)
}

func load_config() {
	/* Load / reload configuration file */
	cfg, err := ini.Load(*configFile)
	checkErr(err)

	durationCounter = cfg.Section("postfixprotect").Key("duration").MustInt64(60)
	mailCounter = cfg.Section("postfixprotect").Key("mailCounter").MustInt(10)
	timeoutPolicyCheck = cfg.Section("postfixprotect").Key("timeoutPolicyCheck").MustInt(10)
	*DEBUG = cfg.Section("postfixprotect").Key("debug").MustBool(true)

	/* connect db and load blacklist database if necessary */
	section := cfg.Section("blacklists").KeysHash()
	if val, ok := section["enabled"]; ok {
		if val == "1" {
			read_db_callback(section, func(r sql.Rows) {
				for r.Next() {
					var domain string
					err := r.Scan(&domain)
					checkErr(err)
					blacklistDomains[domain] = true
				}
				if *DEBUG == true {
					fmt.Println("[blacklisted domains]")
					fmt.Println(blacklistDomains)
				}
			})
		}
	}

	/* connect db and load blacklist database if necessary */
	section = cfg.Section("users").KeysHash()
	if val, ok := section["enabled"]; ok {
		if val == "1" {
			read_db_callback(section, func(r sql.Rows) {
				for r.Next() {
					var sasl_username string
					var sasl_limit int
					err := r.Scan(&sasl_username, &sasl_limit)
					checkErr(err)
					limitMailByUser[sasl_username] = sasl_limit
				}
				if *DEBUG == true {
					fmt.Println("[limits]")
					fmt.Println(limitMailByUser)
				}
			})
		}
	}

	if *DEBUG == true {
		fmt.Printf("[tries] %d per %d seconds\n", mailCounter, durationCounter)
	}
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	load_config()
}

func cleanupUsers() {

}

func main() {
	var wg sync.WaitGroup
	configReload := make(chan os.Signal, 1)
	signal.Notify(configReload, syscall.SIGHUP)

	/* Reload configurations and limits on SIGHUP */
	go func() {
		for range configReload {
			load_config()
		}
	}()

	/* Create send mail and policy-connector  */
	if *RunSendmailProtect == true {
		go listenPort(&wg, handleSendmailConnection, *listenPortSendmail)
		wg.Add(1)
	}
	if *RunSASLpolicyd == true {
		go listenPort(&wg, handlePolicyConnection, *listenPortPolicy)
		wg.Add(1)
	}

	wg.Wait()
	os.Exit(0)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
