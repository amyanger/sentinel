package wire

import "fmt"

// ValidationError describes a single field that failed validation.
// It is returned from Validate and surfaced to clients as HTTP 400 with
// a body naming the failing field.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("wire: %s: %s", e.Field, e.Reason)
}

var allowedSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

var allowedSources = map[string]bool{
	"driver": true, "service": true,
}

// Validate checks a single Event against schema v1 rules.
// Returns nil if valid, or a *ValidationError describing the first failure.
func Validate(e Event) *ValidationError {
	if e.SchemaVersion != CurrentSchemaVersion {
		return &ValidationError{"schema_version", fmt.Sprintf("want %d, got %d", CurrentSchemaVersion, e.SchemaVersion)}
	}
	if e.EventID == "" {
		return &ValidationError{"event_id", "required"}
	}
	if e.ClientID == "" {
		return &ValidationError{"client_id", "required"}
	}
	if e.Timestamp == "" {
		return &ValidationError{"timestamp", "required"}
	}
	if !allowedSources[e.Source] {
		return &ValidationError{"source", fmt.Sprintf("must be one of driver|service, got %q", e.Source)}
	}
	if e.DetectionType == "" {
		return &ValidationError{"detection_type", "required"}
	}
	if !allowedSeverities[e.Severity] {
		return &ValidationError{"severity", fmt.Sprintf("unknown severity %q", e.Severity)}
	}
	if e.Confidence < 0 || e.Confidence > 100 {
		return &ValidationError{"confidence", fmt.Sprintf("must be 0-100, got %d", e.Confidence)}
	}
	if e.Summary == "" {
		return &ValidationError{"summary", "required"}
	}
	return nil
}
