// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Component

package catalog

import (
	"path/filepath"

	"github.com/FuraxFox/malswitch/internal/filehelpers"
	"github.com/FuraxFox/malswitch/internal/submissions"
	log "github.com/sirupsen/logrus"
)

func intializeEntry(tempDir string, hash string) error {
	tempPath := filepath.Join(tempDir, hash)
	err := filehelpers.CreateDirIfNotExist(tempPath)
	if err != nil {
		log.Error("failed to create submission directory:", err)
		return err
	}
	return nil
}

func CreateorUpdateEntry(coldir string, tempDir string, sub *submissions.Submission) error {
	hash := sub.SHA256

	log.Debug(hash)
	// TODO if dir exists update
	// TODO:else initialise

	return intializeEntry(tempDir, hash)
}
