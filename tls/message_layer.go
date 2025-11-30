package tls

import (
	"bytes"
	"fmt"
	"io"
)

type message struct {
	contentType uint8
	content     []byte
}

// handles message fragmentation
type messageLayer interface {
	readMessage() (*message, error)
	writeMessage(*message) (int, error)
}

type messageLayerImpl struct {
	recordLayer recordLayer
	fragmentBuf bytes.Buffer // only handshake messages can be fragmented
}

func newMessageLayerImpl(rl recordLayer) *messageLayerImpl {
	return &messageLayerImpl{
		recordLayer: rl,
	}
}

func (ml *messageLayerImpl) readRecord() (*record, error) {
	record, err := ml.recordLayer.readRecord()
	if err != nil {
		return nil, fmt.Errorf("read record: %w", err)
	}
	return record, nil
}

func (ml *messageLayerImpl) appendFragment() error {
	record, err := ml.readRecord()
	if err != nil {
		return err
	}

	if record.contentType != contentTypeHandshake {
		return fmt.Errorf("expected handshake message, got 0x%02x", record.contentType)
	}

	ml.fragmentBuf.Write(record.fragment)
	return nil
}

func (ml *messageLayerImpl) extendFragmentBuffer(n int) error {
	for ml.fragmentBuf.Len() < n {
		if err := ml.appendFragment(); err != nil {
			return err
		}
	}
	return nil
}

func (ml *messageLayerImpl) readMessage() (*message, error) {
	if ml.fragmentBuf.Len() == 0 {
		record, err := ml.readRecord()
		if err != nil {
			return nil, err
		}

		if record.contentType != contentTypeHandshake {
			return &message{
				contentType: record.contentType,
				content:     record.fragment,
			}, nil
		}
		ml.fragmentBuf.Write(record.fragment)
	}

	if err := ml.extendFragmentBuffer(handshakeHeaderSize); err != nil {
		return nil, err
	}

	header := make([]byte, handshakeHeaderSize)
	if _, err := io.ReadFull(&ml.fragmentBuf, header); err != nil {
		panic(err)
	}

	payloadLen := int(header[1])<<16 + int(header[2])<<8 + int(header[3])
	if err := ml.extendFragmentBuffer(payloadLen); err != nil {
		return nil, err
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(&ml.fragmentBuf, payload); err != nil {
		panic(err)
	}

	return &message{
		contentType: contentTypeHandshake,
		content:     append(header, payload...),
	}, nil
}

func (ml *messageLayerImpl) writeMessage(message *message) (int, error) {
	total := 0
	content := message.content

	for len(content) > 0 {
		chunkSize := min(len(content), maxRecordSize)
		record := &record{
			contentType: message.contentType,
			fragment:    content[:chunkSize],
		}

		if err := ml.recordLayer.writeRecord(record); err != nil {
			return total, err
		}

		content = content[chunkSize:]
		total += chunkSize
	}

	return total, nil
}
