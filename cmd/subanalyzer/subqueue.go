// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/FuraxFox/malswitch/internal/submissions"
	"gopkg.in/yaml.v2"
)

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func readSubmissions(queueDir string) ([]*submissions.Submission, error) {
	// Get a list of files in the incoming directory
	files, err := os.ReadDir(queueDir)
	if err != nil {
		fmt.Println("Error reading incoming directory:", err)
		return nil, err
	}

	// Sort files by modification time in ascending order
	sort.Slice(files, func(i, j int) bool {
		fileI, err := files[i].Info()
		checkErr(err)
		fileJ, err := files[j].Info()
		checkErr(err)
		return fileI.ModTime().Before(fileJ.ModTime())
	})

	// Process files sequentially
	var subQueue []*submissions.Submission
	for _, entry := range files {
		filepath := filepath.Join(queueDir, entry.Name())

		if entry.IsDir() {
			// list the directory content: we expect 1.bin malware, 2.Submission.yaml nothing else
			// TODO check directory content validity
			sub, err := submissions.Read(filepath)
			if err == nil {
				subQueue = append(subQueue, sub)
			}
		}

	}
	return subQueue, nil
}

func processSubmission(sub *submissions.Submission, queueDir string, catalogDir string) error {

	subDir := filepath.Join(queueDir, sub.UUID)
	subPath := filepath.Join(subDir, "Submission.yaml")
	err := sub.Lock()
	if err != nil {
		return err
	}
	defer sub.Unlock()

	// Read the YAML content
	data, err := os.ReadFile(subPath)
	if err != nil {
		return err
	}

	// Parse the YAML content
	var yamlData interface{}
	err = yaml.Unmarshal(data, &yamlData)
	if err != nil {
		return err
	}

	// Display the content
	fmt.Println("File:", subDir)
	fmt.Println(yamlData)

	// Write the content to the outgoing directory
	outgoingFilename := filepath.Join(catalogDir, filepath.Base(subDir))
	err = os.WriteFile(outgoingFilename, data, os.ModePerm)
	if err != nil {
		return err
	}
	fmt.Println(outgoingFilename + " imported to catalog")

	return nil
}
