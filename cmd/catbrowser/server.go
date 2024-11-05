// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.
// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type CatalogEntry struct {
	UUID   string `json:"uuid"`
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	TLP    string `json:"tlp"`
	Size   int64  `json:"size"`
	// ... other fields as needed
}

func CatalogBrowserRequestHandler(w http.ResponseWriter, r *http.Request, ctx *CatalogBrowserContext) {

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
	} else if r.Method == "GET" {
		log.Debug("GET request received for catalog browser")
	} else if r.Method == "POST" {
		log.Debug("POST request received for catalog browser")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := "SELECT uuid, md5, sha1, sha256, sha512, tlp, size FROM catalog"
	args := []interface{}{}

	// Building request
	// TODO make it more generic
	if uuid, ok := r.URL.Query()["uuid"]; ok && len(uuid) > 0 && len(uuid[0]) > 0 {
		query += " WHERE uuid = ?"
		args = append(args, uuid[0])
		log.Debug("looking up entry by subscription UUID <" + uuid[0] + ">")
	} else if md5, ok := r.URL.Query()["md5"]; ok && len(md5) > 0 && len(md5[0]) > 0 {
		query += " WHERE md5 = ?"
		args = append(args, md5[0])
		log.Debug("looking up entry by subscription MD5 <" + md5[0] + ">")
	} else if sha1, ok := r.URL.Query()["sha1"]; ok && len(sha1) > 0 && len(sha1[0]) > 0 {
		query += " WHERE sha1 = ?"
		args = append(args, sha1[0])
		log.Debug("looking up entry by subscription SHA1 <" + sha1[0] + ">")
	} else if sha256, ok := r.URL.Query()["sha256"]; ok && len(sha256) > 0 && len(sha256[0]) > 0 {
		query += " WHERE sha256 = ?"
		args = append(args, sha256[0])
		log.Debug("looking up entry by subscription SHA256 <" + sha256[0] + ">")
	} else if sha512, ok := r.URL.Query()["sha512"]; ok && len(sha512) > 0 && len(sha512[0]) > 0 {
		query += " WHERE sha512 = ?"
		args = append(args, sha512[0])
		log.Debug("looking up entry by subscription SHA512 <" + sha512[0] + ">")
		//} else if len(r.URL.Query()) > 0 {
		//	log.Error("error invalid request")
		//	http.Error(w, "Invalid query parameter", http.StatusBadRequest)
		//	return
	}

	log.Debug("query: " + query)

	// Query value
	rows, err := ctx.Db.Query(query, args...)
	if err != nil {
		log.Error("database request error", err)
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Building response
	var entries []CatalogEntry
	for rows.Next() {
		var entry CatalogEntry
		err := rows.Scan(&entry.UUID, &entry.MD5, &entry.SHA1, &entry.SHA256, &entry.SHA512, &entry.TLP, &entry.Size)
		if err != nil {
			log.Error("database scan error", err)
			http.Error(w, "Database scan error", http.StatusInternalServerError)
			return
		}
		entries = append(entries, entry)
	}
	log.Debug(fmt.Sprintf("returning %d entries", len(entries)))

	answer, err := json.Marshal(entries)
	if err != nil {
		log.Error("error generating response", err)
		http.Error(w, "Error generating response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(answer)
	if err != nil {
		log.Error("error writing response:", err)
		http.Error(w, "Error writing response", http.StatusInternalServerError)
		return
	}

}

func DownloadRequestHandler(w http.ResponseWriter, r *http.Request, ctx *CatalogBrowserContext) {
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
	} else if r.Method == "GET" {
		log.Debug("GET request received for sample download")
	} else if r.Method == "POST" {
		log.Debug("POST request received for sample download")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := "SELECT uuid, md5, sha1, sha256, sha512 FROM catalog"
	args := []interface{}{}

	// Building request
	// TODO make it more generic
	if uuid, ok := r.URL.Query()["uuid"]; ok && len(uuid) > 0 && len(uuid[0]) > 0 {
		query += " WHERE uuid = ?"
		args = append(args, uuid[0])
		log.Debug("looking up entry by subscription UUID <" + uuid[0] + ">")
	} else if md5, ok := r.URL.Query()["md5"]; ok && len(md5) > 0 && len(md5[0]) > 0 {
		query += " WHERE md5 = ?"
		args = append(args, md5[0])
		log.Debug("looking up entry by subscription MD5 <" + md5[0] + ">")
	} else if sha1, ok := r.URL.Query()["sha1"]; ok && len(sha1) > 0 && len(sha1[0]) > 0 {
		query += " WHERE sha1 = ?"
		args = append(args, sha1[0])
		log.Debug("looking up entry by subscription SHA1 <" + sha1[0] + ">")
	} else if sha256, ok := r.URL.Query()["sha256"]; ok && len(sha256) > 0 && len(sha256[0]) > 0 {
		query += " WHERE sha256 = ?"
		args = append(args, sha256[0])
		log.Debug("looking up entry by subscription SHA256 <" + sha256[0] + ">")
	} else if sha512, ok := r.URL.Query()["sha512"]; ok && len(sha512) > 0 && len(sha512[0]) > 0 {
		query += " WHERE sha512 = ?"
		args = append(args, sha512[0])
		log.Debug("looking up entry by subscription SHA512 <" + sha512[0] + ">")
		//} else if len(r.URL.Query()) > 0 {
		//	log.Error("error invalid request")
		//	http.Error(w, "Invalid query parameter", http.StatusBadRequest)
		//	return
	}

	//TODO: download file sample

	log.Debug("query: " + query)

	// Query value
	rows, err := ctx.Db.Query(query, args...)
	if err != nil {
		log.Error("database request error", err)
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Building response
	var entries []CatalogEntry
	for rows.Next() {
		var entry CatalogEntry
		err := rows.Scan(&entry.UUID, &entry.MD5, &entry.SHA1, &entry.SHA256, &entry.SHA512)
		if err != nil {
			log.Error("database scan error", err)
			http.Error(w, "Database scan error", http.StatusInternalServerError)
			return
		}
		entries = append(entries, entry)
	}
	log.Debug(fmt.Sprintf("returning %d entries", len(entries)))

	answer, err := json.Marshal(entries)
	if err != nil {
		log.Error("Error generating response", err)
		http.Error(w, "Error generating response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(answer)
	if err != nil {
		log.Error("error writing response:", err)
		http.Error(w, "Error writing response", http.StatusInternalServerError)
		return
	}

}
