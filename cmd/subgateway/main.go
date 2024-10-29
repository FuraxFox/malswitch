// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission gateway

package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

var LISTEN_PATH string = "/submission-queue"
var LISTEN_ADDR string = "127.0.0.1:8080"
var QUEUE_DIR string = "var/data/submissions"
var TEMP_DIR string = "var/data/temp"

func main() {
	log.SetLevel(log.DebugLevel)
	log.Debug("Starting submission-gateway on " + LISTEN_ADDR + "/" + LISTEN_PATH)
	http.DefaultServeMux.HandleFunc(LISTEN_PATH, SubmissionRequestHandler)
	log.Fatal(http.ListenAndServe(LISTEN_ADDR, nil))
}
