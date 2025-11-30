package tls

const (
	tlsVersion12 uint16 = 0x0303
	tlsVersion13 uint16 = 0x0304

	contentTypeChangeCipherSpec uint8 = 0x14
	contentTypeAlert            uint8 = 0x15
	contentTypeHandshake        uint8 = 0x16
	contentTypeApplicationData  uint8 = 0x17

	handshakeTypeClientHello      uint8 = 0x01
	handshakeTypeNewSessionTicket uint8 = 0x04
	handshakeTypeFinished         uint8 = 0x14

	extensionTypeServerName          uint16 = 0x0000
	extensionTypeSupportedGroups     uint16 = 0x000a
	extensionTypeSignaturaAlgorithms uint16 = 0x000d
	extensionTypeSupportedVersions   uint16 = 0x002b
	extensionTypeKeyShare            uint16 = 0x0033

	tlsAes128GcmSha256 uint16 = 0x1301

	ecdsaSecp256r1Sha256 uint16 = 0x0403

	secp256r1 uint16 = 0x0017

	nullCompressionMethod uint8 = 0x00

	maxRecordSize       = 1 << 14
	handshakeHeaderSize = 4
)
