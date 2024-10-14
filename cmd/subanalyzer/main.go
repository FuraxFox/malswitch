// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

var QUEUE_DIR string = "var/data/submissions"
var TEMP_DIR string = "var/data/temp"

func readSubmission(dirName string) error {
	dirEntries, err := os.ReadDir(dirName)
	if err != nil {
		return fmt.Errorf("failed to read dir: %w", err)
	}
	for _, dirEntry := range dirEntries {
		fmt.Println("== " + dirEntry.Name())
		srcSubDirName := filepath.Join(dirName, dirEntry.Name())

		if dirEntry.IsDir() {

		}
	return nil
}

func main() {
	fmt.Println("Submission analyzer")
}
