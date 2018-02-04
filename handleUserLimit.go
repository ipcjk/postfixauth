package main

import (
	"fmt"
	"time"
)

func isUserInLimit(userHost string) bool {
	var personalMailLimit int
	var personalDurationLimit int

	mu.Lock()
	defer mu.Unlock()

	/* Set defaults for limits from command line parameters */
	personalDurationLimit = *durationCounter
	personalMailLimit = *mailCounter

	/* Check if user exist and overwrite settings */
	if _, ok := limitMailByUser[userHost]; ok {
		personalMailLimit = limitMailByUser[userHost].personalLimit
		personalDurationLimit = limitMailByUser[userHost].personalDurationCounter
	}

	if *debug == true {
		fmt.Printf("(%s)->limit(%d)->duration(%d)\n", userHost, personalMailLimit, personalDurationLimit)
	}

	for i := 0; i < len(currentMailByUser[userHost]); i++ {
		if int(time.Since(currentMailByUser[userHost][i])/time.Second) > personalDurationLimit {
			currentMailByUser[userHost] = append(currentMailByUser[userHost][:i], currentMailByUser[userHost][i+1])
		}
	}

	if len(currentMailByUser[userHost]) >= personalMailLimit {
		return false
	}

	currentMailByUser[userHost] = append(currentMailByUser[userHost], time.Now())
	return true
}
