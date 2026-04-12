package wire

import (
	"encoding/json"
	"testing"
)

func TestEvent_RoundTrip(t *testing.T) {
	original := Event{
		SchemaVersion:   1,
		EventID:         "018f4a2c-7e10-7b1a-9c5d-1f2e3a4b5c6d",
		ClientID:        "acme-07",
		SentinelVersion: "0.3.1",
		Timestamp:       "2026-04-12T14:03:27.412Z",
		Source:          "driver",
		DetectionType:   "DMA_ANOMALY",
		Severity:        "high",
		Confidence:      87,
		Summary:         "Unknown PCIe device",
		Host: Host{
			Hostname:  "TRADING-07",
			OSVersion: "Windows 11 23H2",
			Arch:      "x64",
		},
		Context: map[string]any{
			"pcie_vendor_id": "0x10ee",
			"bus":            "03:00.0",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.EventID != original.EventID {
		t.Errorf("event_id mismatch: got %q, want %q", decoded.EventID, original.EventID)
	}
	if decoded.SchemaVersion != 1 {
		t.Errorf("schema_version mismatch: got %d, want 1", decoded.SchemaVersion)
	}
	if decoded.Host.Hostname != "TRADING-07" {
		t.Errorf("host.hostname mismatch: got %q", decoded.Host.Hostname)
	}
	if decoded.Context["bus"] != "03:00.0" {
		t.Errorf("context.bus mismatch: got %v", decoded.Context["bus"])
	}
}

func TestBatch_Unmarshal(t *testing.T) {
	raw := `{"events":[{"schema_version":1,"event_id":"a","client_id":"c","sentinel_version":"1","timestamp":"2026-04-12T00:00:00Z","source":"driver","detection_type":"DMA_ANOMALY","severity":"high","confidence":80,"summary":"x","host":{"hostname":"h","os_version":"o","arch":"x64"},"context":{}}]}`

	var batch Batch
	if err := json.Unmarshal([]byte(raw), &batch); err != nil {
		t.Fatalf("unmarshal batch: %v", err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(batch.Events))
	}
	if batch.Events[0].EventID != "a" {
		t.Errorf("event id mismatch: got %q", batch.Events[0].EventID)
	}
}
