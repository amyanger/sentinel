// Package wire defines the JSON types used on the network between Sentinel
// clients and the collector. These types are the public schema — changing
// them is a versioned operation.
package wire

// CurrentSchemaVersion is the version the collector understands.
const CurrentSchemaVersion = 1

// Event is one detection event as transmitted over the wire.
type Event struct {
	SchemaVersion   int            `json:"schema_version"`
	EventID         string         `json:"event_id"`
	ClientID        string         `json:"client_id"`
	SentinelVersion string         `json:"sentinel_version"`
	Timestamp       string         `json:"timestamp"` // ISO-8601 UTC, from client
	Source          string         `json:"source"`    // "driver" | "service"
	DetectionType   string         `json:"detection_type"`
	Severity        string         `json:"severity"` // "info"|"low"|"medium"|"high"|"critical"
	Confidence      int            `json:"confidence"` // 0-100
	Summary         string         `json:"summary"`
	Host            Host           `json:"host"`
	Context         map[string]any `json:"context"`
}

// Host describes the client machine that produced an event.
type Host struct {
	Hostname  string `json:"hostname"`
	OSVersion string `json:"os_version"`
	Arch      string `json:"arch"`
}

// Batch is the request body of POST /v1/events.
type Batch struct {
	Events []Event `json:"events"`
}
