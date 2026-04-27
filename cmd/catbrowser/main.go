// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Catalog Browser: navigate in the collection

package main

import (
	"flag"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const CATALOG_URI_PATH = "/catalog"
const DOWNLOAD_URI_PATH = "/download"
const TAGS_URI_PATH = "/tags"
const DEFAULT_LISTEN_ADDRESS = "127.0.0.1:8081"
const DEFAULT_CATALOG_DIR = "var/data/catalog"
const DEFAULT_DB_PATH = "var/databases/catalog.db"

func main() {
	log.SetLevel(log.DebugLevel)

	// Command line flags
	listenAddr := flag.String("addr", DEFAULT_LISTEN_ADDRESS, "Address to listen on")
	catalogDir := flag.String("dir", DEFAULT_CATALOG_DIR, "Directory containing the catalog data")
	dbPath := flag.String("db", DEFAULT_DB_PATH, "Path to the SQLite database")

	catalogPath := CATALOG_URI_PATH
	downloadPath := DOWNLOAD_URI_PATH
	//tagsPath := TAGS_URI_PATH

	// 2. Parse the flags
	flag.Parse()

	// 3. Assign flag values to your context
	// Note: we must dereference the pointers (using *)
	ctx := CatalogBrowserContext{
		CatalogDir:               *catalogDir,
		DbPath:                   *dbPath,
		ServerListenAddr:         *listenAddr,
		ServerCatalogListenPath:  catalogPath,
		ServerDownloadListenPath: downloadPath,
		// ServerTagsListenPath:  *tagsPath,
	}

	err := ctx.OpenDB()
	if err != nil {
		log.Panic("error while opening DB:", err)
	}
	defer ctx.CloseDB()

	log.Debugf("Starting catalog browser on %s%s queue_dir: '%s'",
		ctx.ServerListenAddr, ctx.ServerCatalogListenPath, ctx.CatalogDir)

	// 4. Set up Handlers
	http.DefaultServeMux.HandleFunc(ctx.ServerDownloadListenPath,
		func(w http.ResponseWriter, r *http.Request) {
			DownloadRequestHandler(w, r, &ctx)
		})

	http.DefaultServeMux.HandleFunc(ctx.ServerCatalogListenPath,
		func(w http.ResponseWriter, r *http.Request) {
			CatalogBrowserRequestHandler(w, r, &ctx)
		})

	// 5. Start Server
	// Use the variable from the flag for ListenAndServe
	log.Fatal(http.ListenAndServe(ctx.ServerListenAddr, nil))
}
