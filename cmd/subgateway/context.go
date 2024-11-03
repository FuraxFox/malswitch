// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submission server

package main

type SubmissionServerContext struct {
	TempDir          string
	SubmissionsDir   string
	ServerListenAddr string
	ServerListenPath string
}
