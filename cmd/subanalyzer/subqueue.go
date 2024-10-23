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

func (ctx *SubmissionAnalyzerContext) ReadSubmissions() ([]*submissions.Submission, error) {
	// Get a list of files in the incoming directory
	files, err := os.ReadDir(ctx.SubmissionsDir)
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
		filepath := filepath.Join(ctx.SubmissionsDir, entry.Name())

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

func (ctx *SubmissionAnalyzerContext) ProcessSubmission(sub *submissions.Submission) error {

	subDir := filepath.Join(ctx.SubmissionsDir, sub.UUID)

	// Display the content
	fmt.Println("File:", subDir)
	fmt.Println(sub)

	// Insert the data into the database
	_, err := ctx.Db.Exec("INSERT INTO catalog (uuid, md5, filename, tlp) VALUES (?, ?, ?, ?)",
		sub.UUID, sub.MD5, sub.Filename, sub.TLP)
	if err != nil {
		fmt.Println("Error inserting data:", err)
		return err
	}

	data, err := yaml.Marshal(sub)
	if err != nil {
		fmt.Println("Error serializing data:", err)
		return err
	}

	// Write the content to the outgoing directory
	outgoingFilename := filepath.Join(ctx.CatalogDir, filepath.Base(subDir))
	err = os.WriteFile(outgoingFilename, data, os.ModePerm)
	if err != nil {
		fmt.Println("Error writing catalog manifest:", err)
		return err
	}

	err = sub.Dequeue()
	if err != nil {
		fmt.Println("Error dequeing submission:", err)
		return err
	}

	fmt.Println(outgoingFilename + " imported to catalog")

	return nil
}
