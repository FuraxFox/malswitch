// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

package main

import (
	"net/http"

	"github.com/FuraxFox/malswitch/internal/submissions"
	log "github.com/sirupsen/logrus"
)

func SubmissionRequestHandler(w http.ResponseWriter, r *http.Request, ctx *SubmissionServerContext) {

	if r.Method == "OPTIONS" {
		// preflight request
		headers := w.Header()
		headers.Add("Access-Control-Allow-Origin", "*")
		headers.Add("Vary", "Origin")
		headers.Add("Vary", "Access-Control-Request-Method")
		headers.Add("Vary", "Access-Control-Request-Headers")
		headers.Add("Access-Control-Allow-Headers", "Content-Type, Origin, Accept, token")
		headers.Add("Access-Control-Allow-Methods", "GET, POST,OPTIONS")
		w.WriteHeader(http.StatusOK)
		return
	} else if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Debug("POST request received")

	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB   maximum upload size
	if err != nil {
		log.Error("error parsing form data:", err)
		http.Error(w, "Error parsing form data", http.StatusInternalServerError)
		return
	}
	// Get the uploaded file
	file, handler, err := r.FormFile("sample")
	if err != nil {
		log.Error("no file uploaded:", err)
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	filename := handler.Filename
	defer file.Close()

	// Get the TLP variable
	tlp := r.FormValue("tlp")

	// initialize submission object
	sub, err := submissions.Create(filename, tlp, ctx.SubmissionsDir, ctx.TempDir)
	if err != nil {
		log.Error("error initializing submission:", err)
		http.Error(w, "Error initializing submission", http.StatusInternalServerError)
		return
	}
	// receive file data
	err = sub.Receive(file, ctx.TempDir)
	if err != nil {
		log.Error("error receiveing file:", err)
		http.Error(w, "Error receiving file", http.StatusInternalServerError)
		return
	}

	// compute basic hashes
	err = sub.Hash(ctx.TempDir)
	if err != nil {
		log.Error("error calculating hash:", err)
		http.Error(w, "Error calculating hash", http.StatusInternalServerError)
		return
	}
	// enqueue submission
	err = sub.Enqueue(ctx.SubmissionsDir, ctx.TempDir)
	if err != nil {
		log.Error("error failed to enqueue:", err)
		http.Error(w, "Failed to enqueue", http.StatusInternalServerError)
		return
	}

	log.Info("submission received <TLP:", tlp, " Filename:", filename, " UUID:", sub.UUID, ">")
	answer, err := sub.GetJSON()
	if err != nil {
		log.Error("Error generating response", err)
		http.Error(w, "Error generating response", http.StatusInternalServerError)
		return
	}

	// writing response
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(answer)
	if err != nil {
		log.Error("error writing response:", err)
		http.Error(w, "Error writing response", http.StatusInternalServerError)
		return
	}

}
