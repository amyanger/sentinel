package wire

import "testing"

func validEvent() Event {
	return Event{
		SchemaVersion:   1,
		EventID:         "018f4a2c-7e10-7b1a-9c5d-1f2e3a4b5c6d",
		ClientID:        "c",
		SentinelVersion: "1",
		Timestamp:       "2026-04-12T00:00:00Z",
		Source:          "driver",
		DetectionType:   "DMA_ANOMALY",
		Severity:        "high",
		Confidence:      80,
		Summary:         "x",
		Host:            Host{Hostname: "h", OSVersion: "o", Arch: "x64"},
		Context:         map[string]any{},
	}
}

func TestValidate_Valid(t *testing.T) {
	if err := Validate(validEvent()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_WrongSchemaVersion(t *testing.T) {
	e := validEvent()
	e.SchemaVersion = 2
	err := Validate(e)
	if err == nil || err.Field != "schema_version" {
		t.Errorf("expected schema_version error, got %v", err)
	}
}

func TestValidate_MissingEventID(t *testing.T) {
	e := validEvent()
	e.EventID = ""
	err := Validate(e)
	if err == nil || err.Field != "event_id" {
		t.Errorf("expected event_id error, got %v", err)
	}
}

func TestValidate_MissingClientID(t *testing.T) {
	e := validEvent()
	e.ClientID = ""
	err := Validate(e)
	if err == nil || err.Field != "client_id" {
		t.Errorf("expected client_id error, got %v", err)
	}
}

func TestValidate_MissingTimestamp(t *testing.T) {
	e := validEvent()
	e.Timestamp = ""
	err := Validate(e)
	if err == nil || err.Field != "timestamp" {
		t.Errorf("expected timestamp error, got %v", err)
	}
}

func TestValidate_MissingDetectionType(t *testing.T) {
	e := validEvent()
	e.DetectionType = ""
	err := Validate(e)
	if err == nil || err.Field != "detection_type" {
		t.Errorf("expected detection_type error, got %v", err)
	}
}

func TestValidate_MissingSummary(t *testing.T) {
	e := validEvent()
	e.Summary = ""
	err := Validate(e)
	if err == nil || err.Field != "summary" {
		t.Errorf("expected summary error, got %v", err)
	}
}

func TestValidate_BadSeverity(t *testing.T) {
	e := validEvent()
	e.Severity = "fatal"
	err := Validate(e)
	if err == nil || err.Field != "severity" {
		t.Errorf("expected severity error, got %v", err)
	}
}

func TestValidate_BadSource(t *testing.T) {
	e := validEvent()
	e.Source = "cosmic-ray"
	err := Validate(e)
	if err == nil || err.Field != "source" {
		t.Errorf("expected source error, got %v", err)
	}
}

func TestValidate_ConfidenceOutOfRange(t *testing.T) {
	e := validEvent()
	e.Confidence = 101
	err := Validate(e)
	if err == nil || err.Field != "confidence" {
		t.Errorf("expected confidence error, got %v", err)
	}
}
