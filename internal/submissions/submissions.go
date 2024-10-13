// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submissions: manage user submissions queue

package submissions

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/google/uuid"
)

type Submission struct {
	UUID     string
	SHA256   string
	TLP      string
	Filename string
	TempPath string
}

func Create(sampleFilename string, sampleTLP string, tempDir string) (error, Submission) {
	s := Submission{
		Filename: sampleFilename,
		TLP:      sampleTLP,
	}
	s.UUID = uuid.NewString()
	s.TempPath = filepath.Join(tempDir, s.UUID)
	return nil, s
}

func (s *Submission) Hash(file http.File) error {

	// Calculate the SHA256 hash of the file
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		http.Error(w, "Error calculating hash", http.StatusInternalServerError)
		return err
	}
	hashBytes := hash.Sum(nil)
	hashString := fmt.Sprintf("%x", hashBytes)

	s.SHA256 = hashString

	return nil
}

func (s *Submission) TempFilePath() string {
	return filepath.Join(s.TempPath, s.UUID+".bin")
}
