// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission gateway

package main

import (
	"flag"
	"net/http"

	log "github.com/sirupsen/logrus"
)

var DEFAULT_LISTEN_PATH string = "/submissions"
var DEFAULT_LISTEN_ADDR string = "127.0.0.1:8080"
var DEFAULT_QUEUE_DIR string = "var/data/submissions"
var DEFAULT_TEMP_DIR string = "var/data/temp"

func main() {
	// 1. Define flags with original values as defaults
	listenAddr := flag.String("addr", DEFAULT_LISTEN_ADDR, "HTTP server listen address")
	listenPath := flag.String("path", DEFAULT_LISTEN_PATH, "HTTP endpoint path for submissions")
	queueDir := flag.String("queue", DEFAULT_QUEUE_DIR, "Directory to store incoming submissions")
	tempDir := flag.String("temp", DEFAULT_TEMP_DIR, "Directory for temporary file processing")

	// 2. Parse the command line arguments
	flag.Parse()

	log.SetLevel(log.DebugLevel)

	// 3. Initialize the context using dereferenced pointer values (*name)
	ctx := SubmissionServerContext{
		ServerListenAddr: *listenAddr,
		ServerListenPath: *listenPath,
		TempDir:          *tempDir,
		SubmissionsDir:   *queueDir,
	}

	// 4. Log the configuration (using Debugf for cleaner formatting)
	log.Debugf("Starting submission-gateway on %s%s queue_dir: '%s' temp_dir: '%s'",
		ctx.ServerListenAddr, ctx.ServerListenPath, ctx.SubmissionsDir, ctx.TempDir)

	// 5. Register the handler
	http.DefaultServeMux.HandleFunc(ctx.ServerListenPath,
		func(w http.ResponseWriter, r *http.Request) {
			SubmissionRequestHandler(w, r, &ctx)
		})

	// 6. Start the server
	log.Fatal(http.ListenAndServe(ctx.ServerListenAddr, nil))
}
