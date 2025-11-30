# toy-tls

toy-tls is a minimal TLS 1.3 client built purely for educational purposes.
It demonstrates the core TLS handshake, key derivation, and message exchange.

### Implemented

- Single cryptographic suite: `TLS_AES_128_GCM_SHA256` with `ECDSA_SECP256R1_SHA256`  
- Standard handshake (no client certificates)  
- Server certificate verification  
- Message fragmentation

### Not implemented

- Proper error handling
- Session resumption and key updates  
- HelloRetryRequest and optional extensions  

### Demo

Run a simple HTTPS request:

```bash
go run ./cmd/demo -host example.com -port 443 -v

[ TLS ] 2025/11/30 21:16:54 Client Hello sent:
clientHello {
    hostname:           example.com
    random:             286a9be53ab05ffdc509d9381b6797c503a70cabe071a32f587344f374b25a8e
    pubBytes:           040e896a9a619161fbab7ccbe9b1963ae8f072d88e5d1079b34e49be2a4108f807e8d32ae2caec35c5a3726dea5ba7925a976f292556988d5b569f0e6b37fac318
    supportedVersion:   0x0304
    cipherSuite:        0x1301
    supportedGroup:     0x0017
    signatureAlgorithm: 0x0403
}

[ TLS ] 2025/11/30 21:16:54 Server Hello received:
serverHello {
    random:             d0f2757a2a8da961a4d43867e088a3789131dc95bdf3fec0b4b06acd0a1ce460
    pubBytes:           043604a972c345ab71b0303ed55f0cdc21a9945ce7520c60017bf9078da608b6b1480ae1db1e80e357742a2792bf1f2f397ace087b7ee2dee8bd0cdee8e8a2480d
    version:            0x0304
    cipherSuite:        0x1301
    group:              0x0017
}

[ TLS ] 2025/11/30 21:16:54 Handshake Keys calculated:
trafficKeys {
    secret: d70d5ec57672a2bbdbc041305b65276cc19ae9da54af0f972b7e0d627311b814
    client: encryptionKeys {
                key:      7355abe427267de467b00b5cfe9b0b65
                iv:       a31ff4bf687f4cbc64861095
                finished: e0a1bc6cc5bf9d590b2e5340f94a44397fed91bd029a522812e46fdc2d533fc3
                seq:      0
            }
    server: encryptionKeys {
                key:      355de89fd78e9dd5d6f2fc502c49c54e
                iv:       f9739988d642ffae10786edb
                finished: a42ccc0b15b6d34978ac9cda90c8a0c31daa5ccae8af73f2b5727c366adbf50a
                seq:      0
            }
}

[ TLS ] 2025/11/30 21:16:54 Server Change Cipher Spec received

[ TLS ] 2025/11/30 21:16:54 Encrypted Extensions received (4 bytes)

[ TLS ] 2025/11/30 21:16:54 Server Certificate received and validated:
Certificate {
    subject:        CN=*.example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
    issuer:         CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
    serial:         ad893bafa68b0b7fb7a404f06ecaf9a
    notBefore:      2025-01-15T00:00:00Z
    notAfter:       2026-01-15T23:59:59Z
    dnsNames:       [*.example.com example.com]
    pubKeyAlgo:     ECDSA
    signatureAlgo:  ECDSA-SHA384
}
Certificate {
    subject:        CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
    issuer:         CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
    serial:         b00e92d4d6d731fca3059c7cb1e1886
    notBefore:      2021-04-14T00:00:00Z
    notAfter:       2031-04-13T23:59:59Z
    dnsNames:       []
    pubKeyAlgo:     ECDSA
    signatureAlgo:  ECDSA-SHA384
}
Certificate {
    subject:        CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
    issuer:         CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
    serial:         55556bcf25ea43535c3a40fd5ab4572
    notBefore:      2013-08-01T12:00:00Z
    notAfter:       2038-01-15T12:00:00Z
    dnsNames:       []
    pubKeyAlgo:     ECDSA
    signatureAlgo:  ECDSA-SHA384
}


[ TLS ] 2025/11/30 21:16:54 Server Certificate Verify received and verified:
certificateVerfiy{
    algorithm: 0x0403
    signature: 3044022005d169a02e73d3d008e3c93ac7e6897400cc390ce84aed0098b8b56d45272ac602206284d4c4c27695a360b979e4469db16cc0767ee2c223a576fa387eb022c400c4
}

[ TLS ] 2025/11/30 21:16:54 Server Finished received and verified:
serverFinished {
    verifyData: bf1155980f25e9eb8bd82f2d326da03e2c74fc3bc385bc35fa1d4e9ee8ca6c94
}

[ TLS ] 2025/11/30 21:16:54 Client Finished sent:
clientFinished {
    verifyData: 0d0aa27b9994aa8f48419d9086d2067d91814ba3f85fce7fb5e497afa784aa29
}

[ TLS ] 2025/11/30 21:16:54 Application Keys calculated:
trafficKeys {
    secret: 9e93ba4f82f0d2b2a22f0dfb2211b88268b9c4ccd4d64353be5aa73e8e7087f1
    client: encryptionKeys {
                key:      4d5736f6a95b357121ff82e7ad9aca77
                iv:       0491ff59af6793244a4feafe
                finished: e6e9c242a0383f9a1eff20de5db23b1704b29d010fa979ef51cabc80cef7891a
                seq:      0
            }
    server: encryptionKeys {
                key:      3e594350a77c71644085ff041c5e2b69
                iv:       93b9a12ca060c8b9c31b7c90
                finished: 909e959595ac947d3973deabd90ff68e0a19938341996ad047b1f31c636ec7b1
                seq:      0
            }
}

[ TLS ] 2025/11/30 21:16:54 Application Data sent (37 bytes)

[ TLS ] 2025/11/30 21:16:54 New Session Ticket received

[ TLS ] 2025/11/30 21:16:54 New Session Ticket received

[ TLS ] 2025/11/30 21:16:54 Application Data received (805 bytes)
```
