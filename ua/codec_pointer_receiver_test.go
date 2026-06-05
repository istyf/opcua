package ua

import "testing"

func TestEncodeUsesPointerReceiverBinaryEncoderForSliceElements(t *testing.T) {
	t.Parallel()

	values := []testOptionalCodecValue{
		{Number: 7, Text: "hello", HasText: true},
		{Number: 9},
	}

	encoded, err := Encode(values)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	var got []testOptionalCodecValue
	if _, err := Decode(encoded, &got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if len(got) != len(values) {
		t.Fatalf("decoded len = %d, want %d", len(got), len(values))
	}
	for i := range values {
		if got[i] != values[i] {
			t.Fatalf("decoded value[%d] = %#v, want %#v", i, got[i], values[i])
		}
	}
}

func TestDecodeUsesPointerReceiverBinaryDecoderForSliceElements(t *testing.T) {
	t.Parallel()

	encoded, err := Encode([]testOptionalCodecValue{
		{Number: 1, Text: "abc", HasText: true},
		{Number: 2},
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	var got []testOptionalCodecValue
	if _, err := Decode(encoded, &got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	want := []testOptionalCodecValue{
		{Number: 1, Text: "abc", HasText: true},
		{Number: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("decoded len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decoded value[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestCodecUsesPointerReceiverForNestedStructField(t *testing.T) {
	t.Parallel()

	value := testOptionalCodecContainer{
		Field: testOptionalCodecValue{Number: 11, Text: "nested", HasText: true},
	}

	encoded, err := Encode(&value)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	var got testOptionalCodecContainer
	if _, err := Decode(encoded, &got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if got != value {
		t.Fatalf("decoded container = %#v, want %#v", got, value)
	}
}

func TestCodecPointerCaseStillWorks(t *testing.T) {
	t.Parallel()

	value := &testOptionalCodecValue{Number: 5, Text: "ptr", HasText: true}

	encoded, err := Encode(value)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	var got testOptionalCodecValue
	if _, err := Decode(encoded, &got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if got != *value {
		t.Fatalf("decoded value = %#v, want %#v", got, *value)
	}
}

func TestCodecRoundTripGeneratedStyleOptionalValueSlice(t *testing.T) {
	t.Parallel()

	want := []testOptionalCodecValue{
		{Number: 42, Text: "Hello optional", HasText: true},
		{Number: 77},
	}

	encoded, err := Encode(want)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	var got []testOptionalCodecValue
	if _, err := Decode(encoded, &got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("decoded len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decoded value[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

type testOptionalCodecValue struct {
	Number  int32
	Text    string
	HasText bool
}

func (v *testOptionalCodecValue) Encode() ([]byte, error) {
	buf := NewBuffer(nil)
	var mask byte
	if v.HasText {
		mask = 1
	}
	buf.WriteUint8(mask)
	buf.WriteInt32(v.Number)
	if v.HasText {
		buf.WriteString(v.Text)
	}
	return buf.Bytes(), buf.Error()
}

func (v *testOptionalCodecValue) Decode(b []byte) (int, error) {
	buf := NewBuffer(b)
	mask := buf.ReadUint8()
	v.Number = buf.ReadInt32()
	v.HasText = mask&1 == 1
	if v.HasText {
		v.Text = buf.ReadString()
	} else {
		v.Text = ""
	}
	return buf.Pos(), buf.Error()
}

type testOptionalCodecContainer struct {
	Field testOptionalCodecValue
}
