// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Catalog browser

package main

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

type CatalogBrowserContext struct {
	Db               *sql.DB
	DbPath           string
	CatalogDir       string
	ServerListenAddr string
	ServerListenPath string
}

func (ctx *CatalogBrowserContext) OpenDB() error {

	pwd, _ := os.Getwd()
	log.Debug("opening database " + ctx.DbPath + " (cwd:" + pwd + ")")

	db, err := sql.Open("sqlite3", ctx.DbPath)
	if err != nil {
		log.Error("Error opening catalog database("+pwd+") '"+ctx.DbPath+"'", err)
		return err
	}

	ctx.Db = db

	return nil
}

func (ctx *CatalogBrowserContext) CloseDB() error {
	return ctx.Db.Close()
}
