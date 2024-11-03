// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"fmt"

	"os"
	"path/filepath"
	"sort"

	"github.com/FuraxFox/malswitch/internal/catalog"
	"github.com/FuraxFox/malswitch/internal/submissions"
	log "github.com/sirupsen/logrus"
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
		filePath := filepath.Join(ctx.SubmissionsDir, entry.Name())
		if entry.IsDir() {
			log.Debug("Checking '" + filePath + "' as a submission")
			// list the directory content: we expect 1.bin malware, 2.Submission.yaml nothing else
			// TODO check directory content validity
			sub, err := submissions.Read(filePath)
			if err == nil {
				subQueue = append(subQueue, sub)
				log.Debug("'" + filePath + "' accounted for as a valid submission")
			} else {
				log.Warning("Invalid submission '" + filePath + "'")
			}

		}

	}
	return subQueue, nil
}

func (ctx *SubmissionAnalyzerContext) ProcessSubmission(sub *submissions.Submission) error {
	log.Debug("Processing submission <" + sub.UUID + ">")
	subDir := filepath.Join(ctx.SubmissionsDir, sub.UUID)

	// Display the content
	log.Debug("file:", subDir)
	log.Debug("Submission :" + fmt.Sprintf("%#v", sub))

	// creating the catalog entry from the submission
	cat, err := catalog.CreateOrUpdateEntry(sub, ctx.SubmissionsDir, ctx.CatalogDir)
	if err != nil {
		log.Error("error processing submission <"+sub.UUID+"> to catalog entry:", err)
		return err
	}

	// run the analysis
	err = cat.Analyze(ctx.CatalogDir)
	if err != nil {
		log.Error("error processing analyzing <"+sub.UUID+">:", err)
		return err
	}

	// write the catalog entry to disk
	err = cat.Save(ctx.CatalogDir)
	if err != nil {
		log.Error("error processing submission <"+sub.UUID+"> to catalog:", err)
		return err
	}

	// remove the submission from the queue
	err = sub.Dequeue(ctx.SubmissionsDir)
	if err != nil {
		log.Error("error dequeing submission<"+sub.UUID+">:", err)
		return err
	}

	log.Info("submission<" + sub.UUID + "> imported to catalog as <" + cat.Name() + ">")

	return nil
}
