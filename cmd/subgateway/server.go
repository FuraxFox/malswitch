// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/FuraxFox/malswitch/internal/submissions"
)

func SubmissionRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB   maximum upload size
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusInternalServerError)
		return
	}
	// Get the uploaded file
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	filename := handler.Filename
	defer file.Close()

	// Get the TLP variable
	tlp := r.FormValue("TLP")

	sub, err := submissions.Create(filename, tlp, QUEUE_DIR, TEMP_DIR)
	if err != nil {
		http.Error(w, "Error initializing submission", http.StatusInternalServerError)
		return
	}
	destFPath := sub.TempFilePath()

	// Create a new file on disk
	newFile, err := os.Create(destFPath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer newFile.Close()

	// Copy the uploaded file to the new file
	_, err = io.Copy(newFile, file)
	if err != nil {
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}

	err = sub.Hash()
	if err != nil {
		http.Error(w, "Error calculating hash", http.StatusInternalServerError)
		return
	}

	err = sub.Enqueue(QUEUE_DIR)
	if err != nil {
		http.Error(w, "Failed to enqueue", http.StatusInternalServerError)
		return
	}

	fmt.Println("TLP", tlp)
	fmt.Println("Filename", filename)
	fmt.Println("UUID", sub.UUID)
	fmt.Println("MD5 Hash:", sub.MD5)
	fmt.Println("SHA1 Hash:", sub.SHA1)
	fmt.Println("SHA256 Hash:", sub.SHA256)
	fmt.Println("SHA512 Hash:", sub.SHA512)
	answer, err := sub.GetJSON()

	// writing response
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(answer)
	if err != nil {
		http.Error(w, "Error writing response", http.StatusInternalServerError)
		return
	}

}
