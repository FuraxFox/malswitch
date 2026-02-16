package main

import (
	"encoding/json"
	"log"
	"os"
)

// writeJSONFile serializes data to JSON and saves it to the specified file.
func writeJSONFile(filename string, data interface{}) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create file %s: %v", filename, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Failed to encode JSON to file %s: %v", filename, err)
	}
}
