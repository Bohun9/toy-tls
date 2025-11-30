package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func marshalRecordHeader(contentType uint8, length uint16) []byte {
	header := make([]byte, 5)
	header[0] = contentType
	binary.BigEndian.PutUint16(header[1:3], tlsVersion12)
	binary.BigEndian.PutUint16(header[3:5], length)
	return header
}

type record struct {
	contentType uint8
	fragment    []byte
}

func (r *record) header() []byte {
	return marshalRecordHeader(r.contentType, uint16(len(r.fragment)))
}

func (r *record) marshal() []byte {
	buf := []byte(nil)
	buf = append(buf, r.header()...)
	buf = append(buf, r.fragment...)
	return buf
}

func (r *record) decrypt(keys *encryptionKeys) (*record, error) {
	innerPlaintext, err := keys.decrypt(r.fragment, r.header())
	if err != nil {
		return nil, err
	}

	typeIndex := len(innerPlaintext) - 1
	for typeIndex > 0 && innerPlaintext[typeIndex] == 0 {
		typeIndex--
	}

	return &record{
		contentType: innerPlaintext[typeIndex],
		fragment:    innerPlaintext[:typeIndex],
	}, nil
}

func (r *record) encrypt(keys *encryptionKeys) *record {
	var innerPlaintext bytes.Buffer
	innerPlaintext.Write(r.fragment)
	innerPlaintext.WriteByte(r.contentType)

	encryptedRecordLen := innerPlaintext.Len() + aes128gcmsha256(keys.key).Overhead()
	ciphertextHeader := marshalRecordHeader(contentTypeApplicationData, uint16(encryptedRecordLen))

	encryptedRecord := keys.encrypt(innerPlaintext.Bytes(), ciphertextHeader)
	return &record{
		contentType: contentTypeApplicationData,
		fragment:    encryptedRecord,
	}
}

type recordLayer interface {
	readRecord() (*record, error)
	writeRecord(*record) error
	updateKeys(trafficKeys)
}

type recordLayerImpl struct {
	conn      net.Conn
	writeKeys *encryptionKeys
	readKeys  *encryptionKeys
}

func newRecordLayerImpl(conn net.Conn) *recordLayerImpl {
	return &recordLayerImpl{
		conn: conn,
	}
}

func (rl *recordLayerImpl) updateKeys(tk trafficKeys) {
	rl.writeKeys = tk.client
	rl.readKeys = tk.server
}

func (rl *recordLayerImpl) readRawRecord() (*record, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(rl.conn, header); err != nil {
		return nil, err
	}

	contentType := header[0]
	fragmentLen := binary.BigEndian.Uint16(header[3:5])

	fragment := make([]byte, fragmentLen)
	if _, err := io.ReadFull(rl.conn, fragment); err != nil {
		return nil, err
	}

	return &record{
		contentType: contentType,
		fragment:    fragment,
	}, nil
}

func (rl *recordLayerImpl) readRecord() (*record, error) {
	record, err := rl.readRawRecord()
	if err != nil {
		return nil, err
	}

	if rl.readKeys == nil || record.contentType == contentTypeChangeCipherSpec {
		return record, nil
	} else {
		return record.decrypt(rl.readKeys)
	}
}

func (rl *recordLayerImpl) writeRecord(record *record) error {
	if len(record.fragment) > maxRecordSize {
		return fmt.Errorf("record overflow")
	}

	if rl.writeKeys != nil {
		record = record.encrypt(rl.writeKeys)
	}

	_, err := rl.conn.Write(record.marshal())
	return err
}
