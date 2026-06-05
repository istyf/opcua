package types

import (
	"time"

	"github.com/gopcua/opcua/ua"
)

// Event is the application-facing payload used to emit OPC UA events.
//
// The explicit fields cover BaseEventType. Fields may hold additional event
// fields keyed by a normalized browse path such as "ConditionName" or
// "EnabledState/Id".
type Event struct {
	EventID     []byte
	EventType   *ua.NodeID
	SourceNode  *ua.NodeID
	SourceName  string
	Time        time.Time
	ReceiveTime time.Time
	Message     *ua.LocalizedText
	Severity    uint16

	Fields map[string]*ua.Variant
}
