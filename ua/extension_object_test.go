package ua

import "testing"

func TestExtensionObjectEncodingName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mask uint8
		want string
	}{
		{name: "empty", mask: ExtensionObjectEmpty, want: "empty"},
		{name: "binary", mask: ExtensionObjectBinary, want: "binary"},
		{name: "xml", mask: ExtensionObjectXML, want: "xml"},
		{name: "unknown", mask: 99, want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := extensionObjectEncodingName(tt.mask); got != tt.want {
				t.Fatalf("extensionObjectEncodingName(%d) = %q, want %q", tt.mask, got, tt.want)
			}
		})
	}
}

func TestFormatExpandedNodeIDForLog(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   *ExpandedNodeID
		want string
	}{
		{name: "nil", id: nil, want: "<nil>"},
		{name: "nil node id", id: &ExpandedNodeID{}, want: "<nil node id>"},
		{name: "plain node id", id: &ExpandedNodeID{NodeID: NewNumericNodeID(4, 936)}, want: "ns=4;i=936"},
		{
			name: "node id with namespace uri and server index",
			id: &ExpandedNodeID{
				NodeID:       NewNumericNodeID(4, 936),
				NamespaceURI: "urn:test",
				ServerIndex:  2,
			},
			want: `ns=4;i=936 nsu="urn:test" server_index=2`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatExpandedNodeIDForLog(tt.id); got != tt.want {
				t.Fatalf("formatExpandedNodeIDForLog() = %q, want %q", got, tt.want)
			}
		})
	}
}
