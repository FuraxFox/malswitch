// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Catalog Browser: navigate in the collection

package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

var LISTEN_CATALOG_PATH string = "/catalog"
var LISTEN_DOWNLOAD_PATH string = "/download"
var LISTEN_ADDR string = "127.0.0.1:8081"
var CATALOG_DIR string = "var/data/catalog"
var DB_PATH string = "var/databases/catalog.db"

func main() {
	log.SetLevel(log.DebugLevel)

	ctx := CatalogBrowserContext{
		CatalogDir:               CATALOG_DIR,
		DbPath:                   DB_PATH,
		ServerListenAddr:         LISTEN_ADDR,
		ServerCatalogListenPath:  LISTEN_CATALOG_PATH,
		ServerDownloadListenPath: LISTEN_DOWNLOAD_PATH,
	}

	err := ctx.OpenDB()
	if err != nil {
		log.Panic("error while opening DB:", err)
	}
	defer ctx.CloseDB()

	log.Debug("Starting catalog browser on " +
		ctx.ServerListenAddr + "/" + ctx.ServerCatalogListenPath +
		" queue_dir:'" + ctx.CatalogDir + "' ")

	http.DefaultServeMux.HandleFunc(ctx.ServerDownloadListenPath,
		func(w http.ResponseWriter, r *http.Request) {
			DownloadRequestHandler(w, r, &ctx)
		})
	http.DefaultServeMux.HandleFunc(ctx.ServerCatalogListenPath,
		func(w http.ResponseWriter, r *http.Request) {
			CatalogBrowserRequestHandler(w, r, &ctx)
		})

	log.Fatal(http.ListenAndServe(LISTEN_ADDR, nil))
}
