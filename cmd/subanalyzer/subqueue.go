// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"fmt"

	"os"
	"path/filepath"
	"sort"

	"github.com/FuraxFox/malswitch/internal/submissions"
	log "github.com/sirupsen/logrus"

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
		log.Error("error reading incoming directory:", err)
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
	log.Debug("file:", subDir)
	fmt.Println(sub)

	// Insert the data into the database
	_, err := ctx.Db.Exec(
		"INSERT INTO catalog (uuid, md5, sha1, sha256, sha512, filename, tlp) "+
			" VALUES (?, ?, ?, ?, ?, ?, ?)",
		sub.UUID, sub.MD5, sub.SHA1, sub.SHA256, sub.SHA512, sub.Filename, sub.TLP)
	if err != nil {
		log.Error("error inserting analyzer data to database:", err)
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
