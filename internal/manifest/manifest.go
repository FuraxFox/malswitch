// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Manifest: main functions

package manifest

import "github.com/FuraxFox/malswitch/internal/submissions"

type Manifest struct {
	UUID     string `yaml:"uuid"`
	MD5      string `yaml:"md5"`
	SHA1     string `yaml:"sha1"`
	SHA256   string `yaml:"sha256"`
	SHA512   string `yaml:"sha512"`
	TLP      string `yaml:"tlp"`
	Filename string `yaml:"filename"`
}

func CreateFromSubmission(sub *submissions.Submission) Manifest {
	manif := Manifest{
		UUID:     sub.UUID,
		MD5:      sub.MD5,
		SHA1:     sub.SHA1,
		SHA256:   sub.SHA256,
		SHA512:   sub.SHA512,
		TLP:      sub.TLP,
		Filename: sub.Filename,
	}
	return manif
}
