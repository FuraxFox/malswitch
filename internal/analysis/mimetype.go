package analysis

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/FuraxFox/malswitch/internal/manifest"
	"github.com/h2non/filetype"
	log "github.com/sirupsen/logrus"
)

func AnalyseMimeType(dir string, m *manifest.Manifest) error {

	filePath := filepath.Join(dir, m.Filename)

	// Read the file content
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Error("error reading file:", err)
		return err
	}

	// Determine the file type
	kind, err := filetype.Match(data)
	if err != nil {
		log.Error("error determining file type:", err)
		return err
	}

	if kind == filetype.Unknown {
		log.Warn("File to determine file type for " + m.Filename)
	} else {
		fmt.Printf("File type: %s. MIME: %s\n", kind.Extension, kind.MIME.Value)
	}

	newtag := manifest.Tag{
		Name:      "MimeType",
		Value:     kind.MIME.Type + "/" + kind.MIME.Subtype,
		Parameter: "",
	}

	m.Tags = append(m.Tags, newtag)

	return nil
}
