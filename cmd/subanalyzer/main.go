// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"fmt"
	"os"
	"time"
)

var QUEUE_DIR string = "var/data/submissions"
var TEMP_DIR string = "var/data/temp"
var CAT_DIR string = "var/data/catalog"

func main() {
	submissionDir := QUEUE_DIR
	catalogDir := CAT_DIR

	// Create outgoing directory if it doesn't exist
	err := os.MkdirAll(catalogDir, os.ModePerm)
	if err != nil {
		fmt.Println("Error creating outgoing directory:", err)
		return
	}
	for {
		queue, err := readSubmissions(submissionDir)
		if err != nil {
			fmt.Println("Error reading submissions queue:", err)
			return
		}
		for _, s := range queue {
			err = processSubmission(s, submissionDir, catalogDir)
			if err != nil {
				fmt.Println("Error processing submission:", err)
				return
			}
		}
		time.Sleep(1)
	}
}
