package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStructureDefinitionExtensionObjectEncodeDecodeWithOmittedOptionalFields(t *testing.T) {
	t.Parallel()

	value := &StructureDefinition{
		BaseDataType:  NewNumericNodeID(0, 22),
		StructureType: StructureTypeStructure,
		Fields: []*StructureField{
			{
				Name:      "Temperature",
				DataType:  NewNumericNodeID(0, 11),
				ValueRank: -1,
			},
		},
	}

	encoded, err := NewExtensionObject(value).Encode()
	require.NoError(t, err)

	var decoded ExtensionObject
	_, err = decoded.Decode(encoded)
	require.NoError(t, err)

	got, ok := decoded.Value.(*StructureDefinition)
	require.True(t, ok)
	require.NotNil(t, got.DefaultEncodingID)
	require.Equal(t, NewTwoByteNodeID(0).String(), got.DefaultEncodingID.String())
	require.NotNil(t, got.BaseDataType)
	require.Equal(t, NewNumericNodeID(0, 22).String(), got.BaseDataType.String())
	require.Equal(t, StructureTypeStructure, got.StructureType)
	require.Len(t, got.Fields, 1)
	require.Equal(t, "Temperature", got.Fields[0].Name)
	require.NotNil(t, got.Fields[0].Description)
	require.Empty(t, got.Fields[0].Description.Text)
	require.NotNil(t, got.Fields[0].DataType)
	require.Equal(t, NewNumericNodeID(0, 11).String(), got.Fields[0].DataType.String())
}

func TestEnumDefinitionExtensionObjectEncodeDecodeWithOmittedOptionalFields(t *testing.T) {
	t.Parallel()

	value := &EnumDefinition{
		Fields: []*EnumField{
			{
				Value: 1,
				Name:  "Running",
			},
		},
	}

	encoded, err := NewExtensionObject(value).Encode()
	require.NoError(t, err)

	var decoded ExtensionObject
	_, err = decoded.Decode(encoded)
	require.NoError(t, err)

	got, ok := decoded.Value.(*EnumDefinition)
	require.True(t, ok)
	require.Len(t, got.Fields, 1)
	require.Equal(t, int64(1), got.Fields[0].Value)
	require.Equal(t, "Running", got.Fields[0].Name)
	require.NotNil(t, got.Fields[0].DisplayName)
	require.Empty(t, got.Fields[0].DisplayName.Text)
	require.NotNil(t, got.Fields[0].Description)
	require.Empty(t, got.Fields[0].Description.Text)
}
