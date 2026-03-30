package values

import (
	"time"

	"github.com/gopcua/opcua/ua"
)

func DataValueFromVariant(v *ua.Variant) *ua.DataValue {
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           v,
		SourceTimestamp: time.Now(),
	}
}

func DataValueFromValue(val any) *ua.DataValue {
	// if we already have a data value, just return it.
	switch v := val.(type) {
	case *ua.DataValue:
		return v
	case ua.DataValue:
		return &v
	case ua.Variant:
		return DataValueFromVariant(&v)
	case *ua.Variant:
		return DataValueFromVariant(v)
	case int:
		return DataValueFromVariant(ua.MustVariant(int32(v)))
	}

	return DataValueFromVariant(ua.MustVariant(val))
}
