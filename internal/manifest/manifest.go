// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Manifest: main functions

package manifest

import (
	"os"
	"path/filepath"

	"github.com/FuraxFox/malswitch/internal/submissions"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Manifest struct {
	UUID     string `yaml:"uuid"`
	MD5      string `yaml:"md5"`
	SHA1     string `yaml:"sha1"`
	SHA256   string `yaml:"sha256"`
	SHA512   string `yaml:"sha512"`
	TLP      string `yaml:"tlp"`
	Filename string `yaml:"filename"`
	Tags     []Tag
}

func CreateFromSubmission(sub *submissions.Submission) *Manifest {
	manif := Manifest{
		UUID:     sub.UUID,
		MD5:      sub.MD5,
		SHA1:     sub.SHA1,
		SHA256:   sub.SHA256,
		SHA512:   sub.SHA512,
		TLP:      sub.TLP,
		Filename: sub.Filename,
	}
	return &manif
}

func (m *Manifest) Save(dir string) error {

	data, err := yaml.Marshal(m)
	if err != nil {
		log.Error("Error serializing for catalog entry<"+m.UUID+">:", err)
		return err
	}

	// Write the content to the outgoing directory
	outgoingFilename := filepath.Join(dir, "Manifest.yaml")
	err = os.WriteFile(outgoingFilename, data, os.ModePerm)
	if err != nil {
		log.Error("Error writing catalog for submission<"+m.UUID+">:", err)
		return err
	}
	return nil
}
