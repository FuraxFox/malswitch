/*
Search requests are signed objects describing a search.
They are encrypted before
*/
package aiq

// IOC hash types can be validated against this list
const (
	IOC_TYPE_IP_LIST   = "IP_LIST"
	IOC_TYPE_HASH_LIST = "HASH_LIST"
	IOC_TYPE_YARA_RULE = "YARA_RULE"
	IOC_TYPE_TEXT      = "TEXT"
)

// Represents the structure of a single hash entry to allow for hash type identification.
type HashEntry struct {
	Value string `json:"value"` // The hash string (e.g., a0eebc99da0)
	Type  string `json:"type"`  // e.g., "MD5", "SHA256"
}

type SearchReference struct {
	SearchUUID string `json:"search_uuid"`
	Action     string `json:"search_action"`
}

type SearchMatch struct {
	MatchUUID  string `json:"match_uuid"`
	Reference  string `json:"reference"`
	ContentURL string `json:"content_uri,omitempty"`
	ContenType string `json:"content_type,omitempty"`
}

type RequestType string

const (
	ErrorRequestType                 = "error-request"
	SearchSubmitRequestType          = "search-submit-request"
	SearchAcceptedRequestType        = "search-accepted-request"
	SearchResultPullRequestType      = "search-pull-request"
	SearchResultRequestType          = "search-result-request"
	CommunityRefreshRequestType      = "community-refresh-request"
	CommunityResignRequestType       = "community-resign-request"
	CommunityUpdateRequestType       = "community-update-request"
	CommunityUpdateAcceptedRequestType = "community-update-accepted"
	CommunitySubscribeRequestType    = "community-subscribe-request"
	CommunitySubscriptionQueuedRequestType = "community-subscription-queued"
	CommunityChangeResultRequestType = "community-change-request"
)
