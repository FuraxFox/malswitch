// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission gateway

package main

import (
	"log"
	"net/http"
)

var LISTEN_PATH string = "/submission-queue"
var LISTEN_ADDR string = "127.0.0.1:8080"
var QUEUE_DIR string = "../../var/data/submissions"
var TEMP_DIR string = "../../var/data/temp"

func main() {
	http.HandleFunc(LISTEN_PATH, requestHandler)
	log.Fatal(http.ListenAndServe(LISTEN_ADDR, nil))
}
