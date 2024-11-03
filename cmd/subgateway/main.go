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

	ctx := SubmissionServerContext{
		ServerListenAddr: LISTEN_ADDR,
		ServerListenPath: LISTEN_PATH,
		TempDir:          TEMP_DIR,
		SubmissionsDir:   QUEUE_DIR,
	}

	log.Debug("Starting submission-gateway on " +
		ctx.ServerListenAddr + "/" + ctx.ServerListenPath +
		" queue_dir:'" + ctx.SubmissionsDir + "' temp_dir:'" + ctx.TempDir + "'")
	http.DefaultServeMux.HandleFunc(ctx.ServerListenPath,
		func(w http.ResponseWriter, r *http.Request) {
			SubmissionRequestHandler(w, r, &ctx)
		})
	log.Fatal(http.ListenAndServe(LISTEN_ADDR, nil))
}
