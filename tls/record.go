package tls

import (
	"bytes"
	"encoding/binary"
	"io"
)

func marshalRecordHeader(recordType uint8, length uint16) []byte {
	header := make([]byte, 5)
	header[0] = recordType
	binary.BigEndian.PutUint16(header[1:3], tlsVersion12)
	binary.BigEndian.PutUint16(header[3:5], length)
	return header
}

type record struct {
	typ     uint8
	header  []byte
	payload []byte
}

func newRecord(recordType uint8, payload []byte) *record {
	return &record{
		typ:     recordType,
		header:  marshalRecordHeader(recordType, uint16(len(payload))),
		payload: payload,
	}
}

func (r *record) marshal() []byte {
	buf := []byte(nil)
	buf = append(buf, r.header...)
	buf = append(buf, r.payload...)
	return buf
}

func readRecord(r io.Reader) (*record, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	recordType := header[0]
	payloadLen := binary.BigEndian.Uint16(header[3:5])

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return &record{
		typ:     recordType,
		header:  header,
		payload: payload,
	}, nil
}

func (r *record) decrypt(keys *writeKeys) *record {
	innerPlaintext := keys.decrypt(r.payload, r.header)

	typeIndex := len(innerPlaintext) - 1
	for typeIndex > 0 && innerPlaintext[typeIndex] == 0 {
		typeIndex--
	}

	return &record{
		typ:     innerPlaintext[typeIndex],
		header:  nil,
		payload: innerPlaintext[:typeIndex],
	}
}

func (r *record) encrypt(keys *writeKeys) *record {
	var innerPlaintext bytes.Buffer
	innerPlaintext.Write(r.payload)
	innerPlaintext.WriteByte(r.typ)

	encryptedRecordLen := innerPlaintext.Len() + aes128gcmsha256(keys.key).Overhead()
	ciphertextHeader := marshalRecordHeader(recordTypeApplicationData, uint16(encryptedRecordLen))

	encryptedRecord := keys.encrypt(innerPlaintext.Bytes(), ciphertextHeader)
	return newRecord(recordTypeApplicationData, encryptedRecord)
}
