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
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

/* Some globals */
var debug = flag.Bool("debug", false, "Debug outputs")

/* port for sendmail and policy go routine */
var listenPortSendmail = flag.String("bindSendmail", "localhost:9444", "ip and port for the listening socket for sendmail auth user requests")
var listenPortPolicy = flag.String("bindPolicy", "localhost:9443", "ip and port for the listening socket for policy-connections")
var runSendmailProtect = flag.Bool("sendmailprotect", false, "Run Sendmail policyd")
var runSASLpolicyd = flag.Bool("saslprotect", true, "Run SASL policyd")

/* default variables for our counters */
var durationCounter = flag.Int("duration", 600, "default duration for mailCounters")
var mailCounterPolicyd = flag.Int("mailcounter", 30, "default mailcounter till blocking in duration")
var mailCounterSendmail = flag.Int("mailcountersendmail", 2, "default limit for mails send over the postfix pickup process")
var timeoutPolicyCheck = flag.Int("timeout", 30, "timeout waiting for handle the client connection")

/* whitelist files and enable booleans */
var whiteListMode = flag.Bool("whitelistmode", false, "only allow senders in the whitelist configuration file to send mail")
var whiteListFile = flag.String("whitelist", "virtusertable", "whitelist senders")
var limitsFile = flag.String("limits", "limits.txt", "limits file")
var blackListFile = flag.String("blacklist", "blacklist.txt", "blacklisted sender")

/* greylist or not */
var greyListing = flag.Bool("greylisting", false, "apply greylisting in automode")
var greyListFile = flag.String("greylist", "greylist.txt", "greylist-accounted sender")
var greyListExceptionFile = flag.String("greylistexception", "nogreylist.txt", "don't enforce greylist for this recipients")

/* Postfix strings */
var postfixOkFmt = "200 OK\n"
var postfixErrFmt = "500 Limit reached\n"
var postfixTimeout = "action=451 Timeout client\n\n"
var postfixGreyListing = "action=451 Greylisting activated\n\n"
var postfixPolicyReject = "action=500 Limit reached. Sie haben das aktuelle Versandlimit fuer Ihren Zugang erreicht. " + "Sie duerfen %d Mails in %d Sekunden parallel verschicken, Sie haben allerdings %d bereits versendet. Im Zweifel, wenden Sie sich bitte an den Support.\n\n"
var postfixPolicyBlackListReject = "action=500 Sender blacklisted\n\n"
var postfixPolicyDefaultFmt = "action=DUNNO\n\n"
var postfixPolicyUsername = "sasl_username="
var postfixPolicyRequest = "request="
var postfixPolicySender = "sender="
var postfixPolicyRecipient = "recipient="

/* Record for user limits */
type userLimit struct {
	personalLimit           int
	personalDurationCounter int
}

/* Mutex for map-access */
var mu sync.Mutex
var greyListMu sync.Mutex

/* uMC = userMailCounter */
var currentMailByUser = make(map[string][]time.Time)

/* sMC = staticMailCounters read by txt file */
var limitMailByUser = make(map[string]userLimit)

/*
	blacklisted senderDomains = blacklistSender read by txt file

to be implemented
*/
var blacklistSender = make(map[string]bool)

/*
	whitelist that is read by e.g. postfix user configuration,

e.g. tab seperated
*/
var whitelistSender = make(map[string]bool)

/* greylisting feature */
var greyListTracker = make(map[string]bool)

/* greylisting exception */
var greyListException = make(map[string]bool)

/* to be implemented */
func challengeSender(sender string) error {
	if *debug {
		fmt.Println("Checking", sender)
	}
	/* first check the blacklist, then check whitelistSender map,
	advantage: it will allow us to block even valid sender
	*/
	if _, ok := blacklistSender[sender]; ok {
		return fmt.Errorf("%q is not allowed", sender)
	}

	if _, ok := whitelistSender[sender]; ok {
		return nil
	}

	/* no whitelist mode? then allow "any" address */
	if !*whiteListMode {
		return nil
	}

	/* no blacklist entry found and also we have whitelistmode enabled */
	return fmt.Errorf("%q is not allowed", sender)
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

	signalChanel := make(chan os.Signal, 1)
	signal.Notify(signalChanel, syscall.SIGUSR1)
	signal.Notify(signalChanel, syscall.SIGTERM)
	signal.Notify(signalChanel, syscall.SIGINT)

	/* parse flag  */
	flag.Parse()

	/* Load our txt files */
	loadBlacklist()
	loadLimits()
	loadSenders()
	if *greyListing {
		loadGreyList()
		loadGreyListException()
	}

	if *runSASLpolicyd == true {
		go listenPort(&wg, handlePolicyConnection, *listenPortPolicy)
		wg.Add(1)
	}

	if *runSendmailProtect == true {
		go listenPort(&wg, handleSendmailConnection, *listenPortSendmail)
		wg.Add(1)
	}

	go func() {
		for {
			s := <-signalChanel
			switch s {
			case syscall.SIGTERM:
				saveGreyList()
				os.Exit(0)
			case syscall.SIGINT:
				saveGreyList()
				os.Exit(0)
			case syscall.SIGUSR1:
				log.Println("Benutzerliste mit Limits")
				for users := range limitMailByUser {
					log.Println(users, limitMailByUser[users].personalLimit, limitMailByUser[users].personalDurationCounter)
				}
				log.Println("Aktuelle Limits und Zustellversuche:")
				for limits := range currentMailByUser {
					log.Println(limits, len(currentMailByUser[limits]), currentMailByUser[limits])
				}
				log.Println("Aktuelle Greylistings:")
				for key := range greyListTracker {
					log.Println(key, greyListTracker[key])
				}
			}
		}
	}()

	wg.Wait()
	os.Exit(0)
}

func loadSenders() {
	localwhitelistSender := make(map[string]bool)

	if !*whiteListMode {
		return
	}

	file, err := os.Open(*whiteListFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		fields := strings.Fields(strings.ToLower(scanner.Text()))

		for e := range fields {
			localwhitelistSender[fields[e]] = true
		}

		if *debug {
			fmt.Print("allowed Sender whitelist")
			fmt.Println(fields)
		}
	}

	whitelistSender = localwhitelistSender

}

func loadLimits() {
	locallimitMailByUser := make(map[string]userLimit)

	file, err := os.Open(*limitsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}

		fields := strings.Fields(strings.ToLower(scanner.Text()))
		if len(fields) != 3 {
			continue
		}

		if *debug {
			fmt.Println("loaded limit user list", fields)
		}

		limit, err := strconv.Atoi(fields[1])
		if err != nil {
			limit = *mailCounterPolicyd
			continue
		}

		duration, err := strconv.Atoi(fields[2])
		if err != nil {
			/* take default if err condition */
			duration = *durationCounter
		}
		userHost := fields[0]
		locallimitMailByUser[userHost] = userLimit{
			personalDurationCounter: duration,
			personalLimit:           limit,
		}
	}
	limitMailByUser = locallimitMailByUser
}

func loadBlacklist() {
	localblacklistSender := make(map[string]bool)

	file, err := os.Open(*blackListFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		localblacklistSender[scanner.Text()] = true
	}

	if *debug {
		fmt.Println("Blacklist", localblacklistSender)
	}
	blacklistSender = localblacklistSender
}

func loadGreyList() {
	localGreyList := make(map[string]bool)

	greyListMu.Lock()
	defer greyListMu.Unlock()

	file, err := os.Open(*greyListFile)
	if err != nil {
		greyListTracker = localGreyList
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		localGreyList[scanner.Text()] = true
	}

	if *debug {
		fmt.Println("GreyList", localGreyList)
	}
	greyListTracker = localGreyList
}

func loadGreyListException() {
	localGreyListException := make(map[string]bool)

	greyListMu.Lock()
	defer greyListMu.Unlock()

	file, err := os.Open(*greyListExceptionFile)
	if err != nil {
		log.Println(err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		localGreyListException[scanner.Text()] = true
	}

	if *debug {
		fmt.Println("GreyList-Exception", localGreyListException)
	}
	greyListException = localGreyListException
}

func saveGreyList() {
	greyListMu.Lock()
	defer greyListMu.Unlock()

	if *greyListing {
		log.Println("Saving")
		/* submit to file */
		file, err := os.OpenFile(*greyListFile, os.O_RDWR|os.O_CREATE, 0640)
		if err != nil {
			log.Println(err)
		}
		for key := range greyListTracker {
			fmt.Fprintf(file, "%s\n", key)
		}
		file.Close()
	}
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
