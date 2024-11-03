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
	// ... other fields as needed
}

func CatalogBrowserRequestHandler(w http.ResponseWriter, r *http.Request, ctx *CatalogBrowserContext) {
	if r.Method == "GET" {
		log.Debug("GET request received")
	} else if r.Method == "POST" {
		log.Debug("POST request received")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := "SELECT uuid, md5, sha1, sha256, sha512 FROM catalog"
	args := []interface{}{}

	// Building request
	// TODO make it more generic
	if uuid, ok := r.URL.Query()["entry-id"]; ok && len(uuid) > 0 {
		query += " WHERE uuid = ?"
		args = append(args, uuid[0])
		log.Debug("looking up entry by subscription UUID")
	} else if md5, ok := r.URL.Query()["md5"]; ok && len(md5) > 0 {
		query += " WHERE md5 = ?"
		args = append(args, md5[0])
		log.Debug("looking up entry by subscription MD5")
	} else if sha1, ok := r.URL.Query()["sha1"]; ok && len(sha1) > 0 {
		query += " WHERE sha1 = ?"
		args = append(args, sha1[0])
		log.Debug("looking up entry by subscription SHA1")
	} else if sha256, ok := r.URL.Query()["sha256"]; ok && len(sha256) > 0 {
		query += " WHERE sha256 = ?"
		args = append(args, sha256[0])
		log.Debug("looking up entry by subscription SHA256")
	} else if sha512, ok := r.URL.Query()["sha512"]; ok && len(sha512) > 0 {
		query += " WHERE sha512 = ?"
		args = append(args, sha1[0])
		log.Debug("looking up entry by subscription SHA512")
	} else if len(r.URL.Query()) > 0 {
		log.Error("error invalid request")
		http.Error(w, "Invalid query parameter", http.StatusBadRequest)
		return
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
		err := rows.Scan(&entry.UUID, &entry.MD5, &entry.SHA1, &entry.SHA256, &entry.SHA512)
		if err != nil {
			log.Error("database scan error", err)
			http.Error(w, "Database scan error", http.StatusInternalServerError)
			return
		}
		entries = append(entries, entry)
	}
	log.Debug(fmt.Sprintf("returning %d entries", len(entries)))

	json.NewEncoder(w).Encode(entries)

}
