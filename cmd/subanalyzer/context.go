// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission analyzer

package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

type SubmissionAnalyzerContext struct {
	Db             *sql.DB
	DbPath         string
	CatalogDir     string
	TempDir        string
	SubmissionsDir string
}

func (ctx *SubmissionAnalyzerContext) OpenDB() error {
	db, err := sql.Open("sqlite3", ctx.DbPath)
	if err != nil {
		fmt.Println("Error opening catalog database '", ctx.DbPath, "'", err)
		return err
	}
	// Create the catalog table if it doesn't exist
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS catalog (
            uuid     TEXT PRIMARY KEY,
            md5      TEXT,
			sha1     TEXT,
			sha256   TEXT,
			sha512   TEXT,
            filename TEXT,
            tlp      TEXT
        )
    `)
	if err != nil {
		fmt.Println("Error creating table:", err)
		return err
	}
	return nil
}

func (ctx *SubmissionAnalyzerContext) CloseDB() error {
	return ctx.Db.Close()
}
