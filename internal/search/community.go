package search

type CommunityMember struct {
	Endpoint   string
	SignKey    []byte //ed25519.PublicKey
	EncryptKey []byte //ed25519.PublicKey
}

type Community struct {
	UID         string
	Members     []CommunityMember
	Level       string
	RequestKind bool
}
