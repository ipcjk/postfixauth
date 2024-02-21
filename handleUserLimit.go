package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"
	"time"
)

func isSenderGreyListed(sender, recipient string) bool {

	greyListMu.Lock()
	defer greyListMu.Unlock()

	/* check if recipient is an exception */
	if _, ok := greyListException[recipient]; ok {
		return true
	}

	content := sender + "\\###\\" + recipient

	hash := sha256.New()
	key := hex.EncodeToString(hash.Sum([]byte(content)))

	if _, ok := greyListTracker[key]; !ok {
		greyListTracker[key] = true
		return false
	}

	if *debug {
		log.Println("Found entry for", sender, recipient)
	}

	return true
}

func isUserInLimit(userHost string, defaultDuration int, defaultCounter int) (bool, int, int, int) {
	var personalMailLimit int
	var personalDurationLimit int
	userHost = strings.ToLower(userHost)

	mu.Lock()
	defer mu.Unlock()

	/* Set defaults for limits from command line parameters */
	personalDurationLimit = defaultDuration
	personalMailLimit = defaultCounter

	/* Check if user exist and overwrite settings */
	if _, ok := limitMailByUser[userHost]; ok {
		personalMailLimit = limitMailByUser[userHost].personalLimit
		personalDurationLimit = limitMailByUser[userHost].personalDurationCounter
	}

	if *debug {
		log.Printf("(%s)->limit(%d)->duration(%d)\n", userHost, personalMailLimit, personalDurationLimit)
	}

	/* build up new slice with new time entries */
	var newCurrentMails = make([]time.Time, 0, len(currentMailByUser[userHost]))
	for i := 0; i < len(currentMailByUser[userHost]); i++ {
		if int(time.Since(currentMailByUser[userHost][i])/time.Second) < personalDurationLimit {
			newCurrentMails = append(newCurrentMails, currentMailByUser[userHost][i])
		}
	}
	currentMailByUser[userHost] = nil
	currentMailByUser[userHost] = newCurrentMails

	if len(currentMailByUser[userHost]) > personalMailLimit {
		return false, personalMailLimit, personalDurationLimit, len(currentMailByUser[userHost])
	}

	currentMailByUser[userHost] = append(currentMailByUser[userHost], time.Now())
	return true, personalMailLimit, personalDurationLimit, len(currentMailByUser[userHost])
}
