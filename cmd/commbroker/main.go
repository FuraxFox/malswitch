package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"
	"github.com/sirupsen/logrus"
)

var (
	log       = logrus.New()
	database  *Database
	community aiq.Community
	brokerKey aiq_message.PrivateKeySet
)

const DEFAULT_MAX_AGE = 3600
const DEFAULT_LISTEN_ADDRESS = ":8084"
const DEFAULT_KEY_FILE = "commbroker.priv"
const DEFAULT_DATABASE = "commbroker.db"

func main() {
	// Define flags
	commFile := flag.String("community", "", "Path to the community JSON file (Required)")
	maxAge := flag.Int("max-age", DEFAULT_MAX_AGE, "Maximum age for messages in seconds")
	listenAddr := flag.String("addr", DEFAULT_LISTEN_ADDRESS, "Address to listen on")
	keyFile := flag.String("key-file", DEFAULT_KEY_FILE, "Path to the broker private key file")
	dbFileFlag := flag.String("db-file", DEFAULT_DATABASE, "Path to the broker database file")

	flag.Parse()

	// Validation
	if *commFile == "" {
		fmt.Println("Error: The -community flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	// 3. Load community
	c, err := aiq.LoadCommunity(*commFile)
	if err != nil {
		log.Fatalf("Failed to load community: %v", err)
	}
	community = c

	// 4. Load or generate broker keys
	if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
		log.Infof("Broker key file not found, generating new keys...")
		pub, priv, err := aiq_message.GenerateKeySets()
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		brokerKey = priv

		// Save them
		keyJSON := aiq_message.PrivateKeySetJSON{
			DecryptionKey: base64.StdEncoding.EncodeToString(priv.DecryptionKey),
			SigningKey:    base64.StdEncoding.EncodeToString(priv.SigningKey),
		}
		data, _ := json.MarshalIndent(keyJSON, "", "  ")
		os.WriteFile(*keyFile, data, 0600)
		log.Infof("Broker keys saved to %s", *keyFile)
		log.Infof("Broker Public Signature Key: %s", pub.SignatureKey)
	} else {
		priv, err := aiq_message.LoadPrivateKeys(*keyFile)
		if err != nil {
			log.Fatalf("Failed to load broker keys: %v", err)
		}
		brokerKey = priv
		log.Infof("Broker keys loaded from %s", *keyFile)
	}

	// 5. Init database
	db, err := InitDB(*dbFileFlag)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	database = db
	defer db.Close()

	// 6. Background cleanup
	// Assuming cleanupLoop uses the global maxAge variable or needs to be updated
	// to take a parameter.
	go cleanupLoop(*maxAge)

	// 7. HTTP handlers
	http.HandleFunc("/post-message", postMessageHandler)
	http.HandleFunc("/deliver-message", deliverMessageHandler)

	log.Infof("Community Broker starting on %s (max_age: %ds)", *listenAddr, *maxAge)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
