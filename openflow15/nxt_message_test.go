package openflow15

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PacketIn2UnMarshal(t *testing.T) {
	for _, msgBytes := range [][]byte{
		//{
		//	0, 0, 5, 58, 50, 254, 236, 11, 135, 2, 174, 207, 74, 39, 190, 186, 8, 0, 69, 0, 5, 40, 86, 44, 0, 0, 50, 6, 29, 96, 142, 250, 191, 68, 192, 168, 1, 93, 0, 80, 190, 36, 49, 200, 46, 62, 116, 215, 125, 158, 128, 24, 1, 0, 149, 0, 0, 0, 1, 1, 8, 10, 252, 178, 108, 135, 250, 124, 166, 69, 116, 66, 121, 73, 100, 40, 34, 103, 98, 118, 34, 41, 59, 103, 38, 38, 40, 103, 46, 118, 97, 108, 117, 101, 61, 97, 41, 59, 102, 38, 38, 119, 105, 110, 100, 111, 119, 46, 115, 101, 116, 84, 105, 109, 101, 111, 117, 116, 40, 102, 117, 110, 99, 116, 105, 111, 110, 40, 41, 123, 108, 111, 99, 97, 116, 105, 111, 110, 46, 104, 114, 101, 102, 61, 102, 125, 44, 48, 41, 125, 59, 125, 41, 46, 99, 97, 108, 108, 40, 116, 104, 105, 115, 41, 59, 60, 47, 115, 99, 114, 105, 112, 116, 62, 60, 47, 102, 111, 114, 109, 62, 60, 100, 105, 118, 32, 105, 100, 61, 34, 103, 97, 99, 95, 115, 99, 111, 110, 116, 34, 62, 60, 47, 100, 105, 118, 62, 60, 100, 105, 118, 32, 115, 116, 121, 108, 101, 61, 34, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 56, 51, 37, 59, 109, 105, 110, 45, 104, 101, 105, 103, 104, 116, 58, 51, 46, 53, 101, 109, 34, 62, 60, 98, 114, 62, 60, 100, 105, 118, 32, 105, 100, 61, 34, 112, 114, 109, 34, 62, 60, 115, 116, 121, 108, 101, 62, 46, 115, 122, 112, 112, 109, 100, 98, 89, 117, 116, 116, 95, 95, 109, 105, 100, 100, 108, 101, 45, 115, 108, 111, 116, 45, 112, 114, 111, 109, 111, 123, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 115, 109, 97, 108, 108, 59, 109, 97, 114, 103, 105, 110, 45, 98, 111, 116, 116, 111, 109, 58, 51, 50, 112, 120, 125, 46, 115, 122, 112, 112, 109, 100, 98, 89, 117, 116, 116, 95, 95, 109, 105, 100, 100, 108, 101, 45, 115, 108, 111, 116, 45, 112, 114, 111, 109, 111, 32, 97, 46, 90, 73, 101, 73, 108, 98, 123, 100, 105, 115, 112, 108, 97, 121, 58, 105, 110, 108, 105, 110, 101, 45, 98, 108, 111, 99, 107, 59, 116, 101, 120, 116, 45, 100, 101, 99, 111, 114, 97, 116, 105, 111, 110, 58, 110, 111, 110, 101, 125, 46, 115, 122, 112, 112, 109, 100, 98, 89, 117, 116, 116, 95, 95, 109, 105, 100, 100, 108, 101, 45, 115, 108, 111, 116, 45, 112, 114, 111, 109, 111, 32, 105, 109, 103, 123, 98, 111, 114, 100, 101, 114, 58, 110, 111, 110, 101, 59, 109, 97, 114, 103, 105, 110, 45, 114, 105, 103, 104, 116, 58, 53, 112, 120, 59, 118, 101, 114, 116, 105, 99, 97, 108, 45, 97, 108, 105, 103, 110, 58, 109, 105, 100, 100, 108, 101, 125, 60, 47, 115, 116, 121, 108, 101, 62, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 34, 115, 122, 112, 112, 109, 100, 98, 89, 117, 116, 116, 95, 95, 109, 105, 100, 100, 108, 101, 45, 115, 108, 111, 116, 45, 112, 114, 111, 109, 111, 34, 32, 100, 97, 116, 97, 45, 118, 101, 100, 61, 34, 48, 97, 104, 85, 75, 69, 119, 105, 108, 118, 114, 113, 78, 48, 54, 80, 95, 65, 104, 88, 115, 74, 107, 81, 73, 72, 100, 108, 107, 68, 83, 56, 81, 110, 73, 99, 66, 67, 65, 81, 34, 62, 60, 97, 32, 99, 108, 97, 115, 115, 61, 34, 78, 75, 99, 66, 98, 100, 34, 32, 104, 114, 101, 102, 61, 34, 104, 116, 116, 112, 115, 58, 47, 47, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 47, 117, 114, 108, 63, 113, 61, 104, 116, 116, 112, 115, 58, 47, 47, 98, 108, 111, 103, 46, 103, 111, 111, 103, 108, 101, 47, 111, 117, 116, 114, 101, 97, 99, 104, 45, 105, 110, 105, 116, 105, 97, 116, 105, 118, 101, 115, 47, 100, 105, 118, 101, 114, 115, 105, 116, 121, 47, 112, 114, 105, 100, 101, 45, 50, 48, 50, 51, 47, 37, 51, 70, 117, 116, 109, 95, 115, 111, 117, 114, 99, 101, 37, 51, 68, 104, 112, 112, 38, 97, 109, 112, 59, 115, 111, 117, 114, 99, 101, 61, 104, 112, 112, 38, 97, 109, 112, 59, 105, 100, 61, 49, 57, 48, 51, 54, 48, 49, 51, 38, 97, 109, 112, 59, 99, 116, 61, 51, 38, 97, 109, 112, 59, 117, 115, 103, 61, 65, 79, 118, 86, 97, 119, 50, 98, 57, 108, 50, 88, 90, 95, 95, 79, 79, 80, 104, 118, 82, 99, 78, 55, 70, 81, 112, 99, 38, 97, 109, 112, 59, 115, 97, 61, 88, 38, 97, 109, 112, 59, 118, 101, 100, 61, 48, 97, 104, 85, 75, 69, 119, 105, 108, 118, 114, 113, 78, 48, 54, 80, 95, 65, 104, 88, 115, 74, 107, 81, 73, 72, 100, 108, 107, 68, 83, 56, 81, 56, 73, 99, 66, 67, 65, 85, 34, 32, 114, 101, 108, 61, 34, 110, 111, 102, 111, 108, 108, 111, 119, 34, 62, 72, 111, 110, 111, 114, 105, 110, 103, 32, 80, 114, 105, 100, 101, 60, 47, 97, 62, 60, 115, 112, 97, 110, 62, 32, 97, 110, 100, 32, 115, 117, 112, 112, 111, 114, 116, 105, 110, 103, 32, 116, 104, 101, 32, 76, 71, 66, 84, 81, 43, 32, 99, 111, 109, 109, 117, 110, 105, 116, 121, 60, 47, 115, 112, 97, 110, 62, 60, 47, 100, 105, 118, 62, 60, 47, 100, 105, 118, 62, 60, 47, 100, 105, 118, 62, 60, 115, 112, 97, 110, 32, 105, 100, 61, 34, 102, 111, 111, 116, 101, 114, 34, 62, 60, 100, 105, 118, 32, 115, 116, 121, 108, 101, 61, 34, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 49, 48, 112, 116, 34, 62, 60, 100, 105, 118, 32, 115, 116, 121, 108, 101, 61, 34, 109, 97, 114, 103, 105, 110, 58, 49, 57, 112, 120, 32, 97, 117, 116, 111, 59, 116, 101, 120, 116, 45, 97, 108, 105, 103, 110, 58, 99, 101, 110, 116, 101, 114, 34, 32, 105, 100, 61, 34, 87, 113, 81, 65, 78, 98, 34, 62, 60, 97, 32, 104, 114, 101, 102, 61, 34, 47, 105, 110, 116, 108, 47, 101, 110, 47, 97, 100, 115, 47, 34, 62, 65, 100, 118, 101, 114, 116, 105, 115, 105, 110, 103, 60, 47, 97, 62, 60, 97, 32, 104, 114, 101, 102, 61, 34, 47, 115, 101, 114, 118, 105, 99, 101, 115, 47, 34, 62, 66, 117, 115, 105, 110, 101, 115, 115, 32, 83, 111, 108, 117, 116, 105, 111, 110, 115, 60, 47, 97, 62, 60, 97, 32, 104, 114, 101, 102, 61, 34, 47, 105, 110, 116, 108, 47, 101, 110, 47, 97, 98, 111, 117, 116, 46, 104, 116, 109, 108, 34, 62, 65, 98, 111, 117, 116, 32, 71, 111, 111, 103, 108, 101, 60, 47, 97, 62, 60, 47, 100, 105, 118, 62, 60, 47, 100, 105, 118, 62, 60, 112, 32, 115, 116, 121, 108, 101, 61, 34, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 56, 112, 116, 59, 99, 111, 108, 111, 114, 58, 35, 55, 48, 55, 53, 55, 97, 34, 62, 38, 99, 111, 112, 121, 59, 32, 50, 48, 50, 51, 32, 45, 32, 60, 97, 32, 104, 114, 101, 102, 61, 34, 47, 105, 110, 116, 108, 47, 101, 110, 47, 112, 111, 108, 105, 99, 105, 101, 115, 47, 112, 114, 105, 118, 97, 99, 121, 47, 34, 62, 80, 114, 105, 118, 97, 99, 121, 60, 47, 97, 62, 32, 13, 10, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 0, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 71, 1, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 109, 128, 0, 0, 4, 0, 0, 0, 2, 128, 0, 10, 2, 8, 0, 128, 1, 0, 8, 0, 0, 1, 2, 0, 0, 0, 8, 0, 1, 211, 8, 0, 0, 0, 42, 0, 0, 0, 255, 0, 1, 212, 2, 255, 240, 0, 1, 214, 4, 0, 0, 0, 3, 0, 1, 216, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 240, 4, 192, 168, 1, 93, 0, 1, 242, 4, 142, 250, 191, 68, 0, 1, 238, 1, 6, 0, 1, 248, 2, 190, 36, 0, 1, 250, 2, 0, 80, 0, 0, 0, 0, 8, 0, 72, 0, 0, 0, 0, 128, 0, 0, 20, 215, 69, 17, 182, 155, 77, 98, 59, 44, 10, 115, 141, 182, 17, 49, 28, 0, 0, 0, 0, 128, 3, 0, 4, 0, 0, 0, 0, 128, 6, 0, 24, 0, 0, 0, 0, 255, 255, 0, 16, 0, 0, 35, 32, 0, 14, 255, 248, 27, 0, 0, 0, 128, 8, 0, 8, 0, 0, 0, 2, 0, 7, 0, 5, 2, 0, 0, 0,
		//},
		{
			0, 0, 0, 146, 18, 140, 235, 64, 244, 97, 250, 225, 185, 29, 98, 76, 8, 0, 69, 0, 0, 128, 151, 168, 0, 0, 64, 17, 95, 107, 192, 168, 1, 5, 192, 168, 1, 4, 74, 57, 20, 82, 0, 108, 13, 49, 117, 159, 251, 198, 61, 109, 42, 121, 234, 20, 98, 87, 11, 180, 91, 59, 161, 218, 102, 137, 89, 223, 92, 99, 99, 210, 6, 161, 88, 61, 58, 221, 130, 3, 79, 13, 108, 100, 49, 145, 217, 127, 208, 138, 83, 143, 196, 218, 213, 142, 95, 176, 200, 34, 238, 76, 163, 124, 177, 196, 162, 67, 103, 87, 121, 250, 175, 94, 99, 41, 35, 235, 175, 72, 139, 243, 88, 174, 46, 60, 46, 253, 234, 183, 153, 195, 182, 226, 236, 29, 141, 149, 78, 195, 170, 167, 98, 114, 152, 155, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 28, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 31, 2, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 76, 128, 0, 0, 4, 0, 0, 0, 6, 128, 1, 0, 8, 2, 64, 0, 3, 0, 0, 0, 5, 128, 1, 3, 16, 0, 0, 0, 25, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 128, 1, 4, 8, 0, 1, 0, 0, 0, 0, 0, 3, 128, 1, 7, 16, 0, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 6, 1, 1, 0, 0,
		},
		{
			0, 0, 0, 146, 18, 140, 235, 64, 244, 97, 250, 225, 185, 29, 98, 76, 8, 0, 69, 0, 0, 128, 151, 168, 0, 0, 64, 17, 95, 107, 192, 168, 1, 5, 192, 168, 1, 4, 74, 57, 20, 82, 0, 108, 13, 49, 117, 159, 251, 198, 61, 109, 42, 121, 234, 20, 98, 87, 11, 180, 91, 59, 161, 218, 102, 137, 89, 223, 92, 99, 99, 210, 6, 161, 88, 61, 58, 221, 130, 3, 79, 13, 108, 100, 49, 145, 217, 127, 208, 138, 83, 143, 196, 218, 213, 142, 95, 176, 200, 34, 238, 76, 163, 124, 177, 196, 162, 67, 103, 87, 121, 250, 175, 94, 99, 41, 35, 235, 175, 72, 139, 243, 88, 174, 46, 60, 46, 253, 234, 183, 153, 195, 182, 226, 236, 29, 141, 149, 78, 195, 170, 167, 98, 114, 152, 155, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 28, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 31, 2, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 64, 128, 0, 0, 4, 0, 0, 0, 6, 128, 1, 1, 16, 2, 64, 0, 3, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 128, 1, 3, 16, 0, 0, 0, 14, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 128, 1, 4, 8, 0, 1, 0, 0, 0, 0, 0, 3, 0, 7, 0, 6, 1, 1, 0, 0,
		},
		{
			0, 0, 0, 146, 18, 140, 235, 64, 244, 97, 250, 225, 185, 29, 98, 76, 8, 0, 69, 0, 0, 128, 81, 197, 0, 0, 64, 17, 165, 78, 192, 168, 1, 5, 192, 168, 1, 4, 74, 57, 20, 82, 0, 108, 39, 22, 38, 140, 4, 111, 143, 183, 249, 172, 140, 17, 90, 252, 24, 153, 45, 23, 130, 161, 238, 104, 89, 18, 12, 49, 241, 43, 100, 179, 102, 188, 140, 42, 221, 93, 185, 100, 143, 105, 135, 253, 204, 36, 247, 68, 5, 239, 57, 213, 97, 86, 73, 13, 73, 247, 250, 181, 202, 140, 158, 63, 190, 231, 49, 20, 242, 192, 121, 129, 5, 81, 253, 104, 171, 241, 45, 46, 189, 211, 37, 123, 31, 187, 181, 253, 60, 109, 192, 144, 230, 234, 108, 149, 104, 131, 163, 221, 165, 41, 249, 138, 0, 0, 0, 0, 0, 0, 0, 3, 0, 5, 28, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0, 0, 35, 2, 0, 0, 0, 0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 6, 0, 76, 128, 0, 0, 4, 0, 0, 0, 6, 128, 1, 0, 8, 2, 64, 0, 3, 0, 0, 0, 5, 128, 1, 3, 16, 0, 0, 0, 25, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 128, 1, 4, 8, 0, 1, 0, 0, 0, 0, 0, 3, 128, 1, 7, 16, 0, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 6, 1, 1, 0, 0,
		},
	} {
		pktIn2 := new(PacketIn2)
		err := pktIn2.UnmarshalBinary(msgBytes)
		assert.NoError(t, err)
		for _, prop := range pktIn2.Props {
			fmt.Printf("%+v\n", prop)
			metaField, ok := prop.(*PacketIn2PropMetadata)
			if ok {
				for _, mf := range metaField.Fields {
					valueBytes, _ := mf.Value.MarshalBinary()
					var maskBytes []byte
					if mf.HasMask {
						maskBytes, _ = mf.Mask.MarshalBinary()
					}
					fmt.Printf("found reg match field class %d, field %d, value %v, mask %v\n", mf.Class, mf.Field, valueBytes, maskBytes)
				}
			}
		}
		marshalBytes, err := pktIn2.MarshalBinary()
		assert.NoError(t, err)
		assert.Equal(t, msgBytes, marshalBytes)
		newPktIn2 := new(PacketIn2)
		err = newPktIn2.UnmarshalBinary(marshalBytes)
		assert.NoError(t, err)
	}
}

func Test_PacketIn2Properties(t *testing.T) {
	continuation := &PacketIn2PropContinuation{
		Continuation: []byte{1, 2, 0xf, 0xa},
		PropHeader: &PropHeader{
			Type: NXPINT_CONTINUATION,
		},
	}
	continuation.Length = continuation.Len()
	data, err := continuation.MarshalBinary()
	assert.NoError(t, err)
	continuation2 := new(PacketIn2PropContinuation)
	assert.NoError(t, continuation2.UnmarshalBinary(data))
	assert.Equal(t, continuation2, continuation)
}
