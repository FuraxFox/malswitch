// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"flag"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

var DEFAULT_QUEUE_DIR string = "var/data/submissions"
var DEFAULT_TEMP_DIR string = "var/data/temp"
var DEFAULT_CATALOG_DIR string = "var/data/catalog"
var DEFAULT_DB_PATH string = "var/databases/catalog.db"

func main() {
	// 1. Define flags with your original constants as default values
	queueDir := flag.String("queue", DEFAULT_QUEUE_DIR, "Directory to watch for new submissions")
	tempDir := flag.String("temp", DEFAULT_TEMP_DIR, "Directory for temporary processing")
	catalogDir := flag.String("catalog", DEFAULT_CATALOG_DIR, "Directory where analyzed malware is stored")
	dbPath := flag.String("db", DEFAULT_DB_PATH, "Path to the SQLite catalog database")

	// 2. Parse the flags
	flag.Parse()

	log.SetLevel(log.DebugLevel)

	// 3. Initialize context using the dereferenced flag values
	ctx := SubmissionAnalyzerContext{
		CatalogDir:     *catalogDir,
		TempDir:        *tempDir,
		SubmissionsDir: *queueDir,
		DbPath:         *dbPath,
	}

	log.Debugf("Starting submission-analyzer: queue='%s', temp='%s', db='%s'",
		ctx.SubmissionsDir, ctx.TempDir, ctx.DbPath)

	err := ctx.OpenDB()
	if err != nil {
		log.Panic("error while opening DB:", err)
	}
	defer ctx.CloseDB()

	// 4. Create catalog directory if it doesn't exist
	err = os.MkdirAll(ctx.CatalogDir, os.ModePerm)
	if err != nil {
		log.Errorf("error creating catalog directory (%s): %v", ctx.CatalogDir, err)
		return
	}

	log.Infof("Starting to analyze from queue '%s'", ctx.SubmissionsDir)

	// 5. Main Processing Loop
	for {
		queue, err := ctx.ReadSubmissions()
		if err != nil {
			log.Errorf("error reading submissions queue: %v", err)
			time.Sleep(2 * time.Second) // Wait a bit before retrying on error
			continue
		}

		for _, s := range queue {
			log.Infof("processing submission %s", s.UUID)
			err = ctx.ProcessSubmission(s)
			if err != nil {
				log.Errorf("error processing submission %s: %v", s.UUID, err)
				// Depending on your logic, you might want to continue to the next one
				continue
			}
		}

		time.Sleep(100 * time.Millisecond)
	}
}
