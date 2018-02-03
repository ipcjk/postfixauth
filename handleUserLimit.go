package main

import (
	"fmt"
	"time"
)

func isUserInLimit(userHost string) bool {
	var personalMailLimit int
	mu.Lock()
	defer mu.Unlock()

	for i := 0; i < len(currentMailByUser[userHost]); i++ {
		if int64(time.Since(currentMailByUser[userHost][i])/time.Second) > *durationCounter {
			currentMailByUser[userHost] = append(currentMailByUser[userHost][:i], currentMailByUser[userHost][i+1])
		}
	}

	personalMailLimit = *mailCounter
	if _, ok := limitMailByUser[userHost]; ok {
		personalMailLimit = limitMailByUser[userHost]
		if *debug == true {
			fmt.Printf("(%s)->limit(%d)\n", userHost, personalMailLimit)
		}
	}

	if len(currentMailByUser[userHost]) >= personalMailLimit {
		return false
	}

	currentMailByUser[userHost] = append(currentMailByUser[userHost], time.Now())
	return true
}
