// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

var QUEUE_DIR string = "var/data/submissions"
var TEMP_DIR string = "var/data/temp"
var CAT_DIR string = "var/data/catalog"
var DB_PATH string = "var/databases/catalog.db"

func main() {

	log.SetLevel(log.DebugLevel)

	ctx := SubmissionAnalyzerContext{
		CatalogDir:     CAT_DIR,
		TempDir:        TEMP_DIR,
		SubmissionsDir: QUEUE_DIR,
		DbPath:         DB_PATH,
	}

	log.Debug("Starting submission-analyzer on queue_dir:" +
		"'" + QUEUE_DIR + "' temp_dir:'" + TEMP_DIR + "' cat_dir:'" + DB_PATH + "'")

	err := ctx.OpenDB()
	if err != nil {
		log.Error("error while opening DB", err)
		return
	}
	defer ctx.CloseDB()

	// Create outgoing directory if it doesn't exist
	err = os.MkdirAll(ctx.CatalogDir, os.ModePerm)
	if err != nil {
		log.Error("error creating outgoing directory("+ctx.CatalogDir+"):", err)
		return
	}
	log.Info("starting to analyse from queue '" + ctx.SubmissionsDir + "'")
	for {
		queue, err := ctx.ReadSubmissions()
		if err != nil {
			log.Error("error reading submissions queue:", err)
			return
		}
		for _, s := range queue {
			err = ctx.ProcessSubmission(s)
			if err != nil {
				log.Error("error processing submission:", err)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}
