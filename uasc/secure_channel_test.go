package uasc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	uatest "github.com/gopcua/opcua/tests/python"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

func TestNewRequestMessage(t *testing.T) {
	fixedTime := func() time.Time { return time.Date(2019, 1, 1, 12, 13, 14, 0, time.UTC) }

	buildSecureChannel := func(sc *SecureChannel, instance *channelInstance) *SecureChannel {
		if instance == nil {
			instance = newChannelInstance(sc)
		}
		sc.activeInstance = instance
		sc.activeInstance.sc = sc
		return sc
	}

	tests := []struct {
		name      string
		sechan    *SecureChannel
		req       ua.Request
		authToken *ua.NodeID
		timeout   time.Duration
		m         *Message
	}{
		{
			name: "first-request",
			sechan: buildSecureChannel(&SecureChannel{
				cfg: &Config{},
				// reqhdr: &ua.RequestHeader{},
				time: fixedTime,
			}, nil),
			req: &ua.ReadRequest{},
			m: &Message{
				MessageHeader: &MessageHeader{
					Header: &Header{
						MessageType: MessageTypeMessage,
						ChunkType:   ChunkTypeFinal,
					},
					SymmetricSecurityHeader: &SymmetricSecurityHeader{},
					SequenceHeader: &SequenceHeader{
						SequenceNumber: 1,
						RequestID:      1,
					},
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.ReadRequest_Encoding_DefaultBinary),
				Service: &ua.ReadRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           fixedTime(),
						RequestHandle:       1,
						AdditionalHeader:    ua.NewExtensionObject(nil),
					},
				},
			},
		},
		{
			name: "subsequent-request",
			sechan: buildSecureChannel(
				&SecureChannel{
					cfg:       &Config{},
					requestID: 555,
					// reqhdr: &ua.RequestHeader{
					// 	RequestHandle: 444,
					// },
					time: fixedTime,
				},
				&channelInstance{
					sequenceNumber: 777,
				},
			),
			req: &ua.ReadRequest{},
			m: &Message{
				MessageHeader: &MessageHeader{
					Header: &Header{
						MessageType: MessageTypeMessage,
						ChunkType:   ChunkTypeFinal,
					},
					SymmetricSecurityHeader: &SymmetricSecurityHeader{},
					SequenceHeader: &SequenceHeader{
						SequenceNumber: 778,
						RequestID:      556,
					},
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.ReadRequest_Encoding_DefaultBinary),
				Service: &ua.ReadRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           fixedTime(),
						RequestHandle:       556,
						AdditionalHeader:    ua.NewExtensionObject(nil),
					},
				},
			},
		},
		{
			name: "counter-rollover",
			sechan: buildSecureChannel(
				&SecureChannel{
					cfg:       &Config{},
					requestID: math.MaxUint32,
					time:      fixedTime,
				},
				&channelInstance{
					sequenceNumber: math.MaxUint32 - 1023,
				}),
			req: &ua.ReadRequest{},
			m: &Message{
				MessageHeader: &MessageHeader{
					Header: &Header{
						MessageType: MessageTypeMessage,
						ChunkType:   ChunkTypeFinal,
					},
					SymmetricSecurityHeader: &SymmetricSecurityHeader{},
					SequenceHeader: &SequenceHeader{
						SequenceNumber: 1,
						RequestID:      1,
					},
				},
				TypeID: ua.NewFourByteExpandedNodeID(0, id.ReadRequest_Encoding_DefaultBinary),
				Service: &ua.ReadRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           fixedTime(),
						RequestHandle:       1,
						AdditionalHeader:    ua.NewExtensionObject(nil),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := tt.sechan.activeInstance.newRequestMessage(tt.req, tt.sechan.nextRequestID(), tt.authToken, tt.timeout)
			require.NoError(t, err)
			require.Equal(t, tt.m, m)
		})
	}
}

func TestValidateIncomingOpenSecureChannelPolicy(t *testing.T) {
	t.Parallel()

	serverChannel := &SecureChannel{
		kind: server,
		cfg: &Config{
			ServerSecurityPolicyValidator: func(policy string) error {
				if policy != ua.SecurityPolicyURIBasic256Sha256 {
					return ua.StatusBadSecurityPolicyRejected
				}
				return nil
			},
		},
	}

	if err := serverChannel.validateIncomingOpenSecureChannelPolicy(ua.SecurityPolicyURIBasic256Sha256); err != nil {
		t.Fatalf("expected policy to be accepted, got %v", err)
	}
	if err := serverChannel.validateIncomingOpenSecureChannelPolicy(ua.SecurityPolicyURIBasic256); err != ua.StatusBadSecurityPolicyRejected {
		t.Fatalf("expected %v, got %v", ua.StatusBadSecurityPolicyRejected, err)
	}

	clientChannel := &SecureChannel{
		kind: client,
		cfg: &Config{
			ServerSecurityPolicyValidator: func(string) error {
				return ua.StatusBadSecurityPolicyRejected
			},
		},
	}
	if err := clientChannel.validateIncomingOpenSecureChannelPolicy(ua.SecurityPolicyURIBasic256); err != nil {
		t.Fatalf("expected client channel to ignore server policy validator, got %v", err)
	}
}

func TestValidateIncomingOpenSecureChannelRequest(t *testing.T) {
	t.Parallel()

	serverChannel := &SecureChannel{
		kind: server,
		cfg: &Config{
			ServerOpenSecureChannelValidator: func(policy string, mode ua.MessageSecurityMode) error {
				if policy != ua.SecurityPolicyURIBasic256Sha256 || mode != ua.MessageSecurityModeSignAndEncrypt {
					return ua.StatusBadSecurityModeRejected
				}
				return nil
			},
		},
	}

	if err := serverChannel.validateIncomingOpenSecureChannelRequest(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt); err != nil {
		t.Fatalf("expected policy/mode to be accepted, got %v", err)
	}
	if err := serverChannel.validateIncomingOpenSecureChannelRequest(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign); err != ua.StatusBadSecurityModeRejected {
		t.Fatalf("expected %v, got %v", ua.StatusBadSecurityModeRejected, err)
	}

	clientChannel := &SecureChannel{
		kind: client,
		cfg: &Config{
			ServerOpenSecureChannelValidator: func(string, ua.MessageSecurityMode) error {
				return ua.StatusBadSecurityModeRejected
			},
		},
	}
	if err := clientChannel.validateIncomingOpenSecureChannelRequest(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign); err != nil {
		t.Fatalf("expected client channel to ignore server request validator, got %v", err)
	}
}

func TestPrepareOpeningInstanceForOpenPreservesNegotiatedSecurityMode(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
	require.NoError(t, err)

	keyBlock, _ := pem.Decode(keyPEM)
	localKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)

	certBlock, _ := pem.Decode(certPEM)
	remoteCert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)

	sc := &SecureChannel{
		kind: client,
		c:    &uacp.Conn{},
		cfg: &Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			SecurityMode:      ua.MessageSecurityModeSign,
			LocalKey:          localKey,
		},
		openingInstance: newChannelInstance(nil),
	}
	sc.openingInstance.sc = sc

	chunk := &MessageChunk{
		MessageHeader: &MessageHeader{
			Header: NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 1),
			AsymmetricSecurityHeader: &AsymmetricSecurityHeader{
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
				SenderCertificate: remoteCert.Raw,
			},
		},
	}

	err = sc.prepareOpeningInstanceForOpen(chunk)
	require.NoError(t, err)
	require.Equal(t, ua.MessageSecurityModeSign, sc.cfg.SecurityMode)
	require.NotNil(t, sc.openingInstance.algo)
}

func TestValidateIncomingOpenSecureChannelPolicyDoesNotActivateChannel(t *testing.T) {
	t.Parallel()

	serverChannel := &SecureChannel{
		kind:      server,
		cfg:       &Config{},
		instances: make(map[uint32][]*channelInstance),
	}
	serverChannel.openingInstance = newChannelInstance(serverChannel)
	serverChannel.cfg.ServerSecurityPolicyValidator = func(string) error {
		return ua.StatusBadSecurityPolicyRejected
	}

	err := serverChannel.validateIncomingOpenSecureChannelPolicy(ua.SecurityPolicyURIBasic256Sha256)
	if err != ua.StatusBadSecurityPolicyRejected {
		t.Fatalf("expected %v, got %v", ua.StatusBadSecurityPolicyRejected, err)
	}
	if serverChannel.activeInstance != nil {
		t.Fatalf("expected active instance to remain nil after policy rejection")
	}
	if len(serverChannel.instances) != 0 {
		t.Fatalf("expected no registered channel instances after policy rejection, got %d", len(serverChannel.instances))
	}
	if serverChannel.openingInstance == nil || serverChannel.openingInstance.state != channelOpening {
		t.Fatalf("expected opening instance to remain in opening state after policy rejection")
	}
}

func TestHandleOpenSecureChannelRequestRejectsDisabledModeBeforeActivation(t *testing.T) {
	t.Parallel()

	serverChannel := &SecureChannel{
		kind:      server,
		cfg:       &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256},
		instances: make(map[uint32][]*channelInstance),
	}
	serverChannel.openingInstance = newChannelInstance(serverChannel)
	serverChannel.cfg.ServerOpenSecureChannelValidator = func(_ string, mode ua.MessageSecurityMode) error {
		if mode != ua.MessageSecurityModeSignAndEncrypt {
			return ua.StatusBadSecurityModeRejected
		}
		return nil
	}

	req := &ua.OpenSecureChannelRequest{
		RequestHeader: &ua.RequestHeader{
			AuthenticationToken: ua.NewTwoByteNodeID(0),
			RequestHandle:       1,
			AdditionalHeader:    ua.NewExtensionObject(nil),
		},
		ClientProtocolVersion: 0,
		RequestType:           ua.SecurityTokenRequestTypeIssue,
		SecurityMode:          ua.MessageSecurityModeSign,
	}

	err := serverChannel.handleOpenSecureChannelRequest(t.Context(), 1, req)
	if err != ua.StatusBadSecurityModeRejected {
		t.Fatalf("expected %v, got %v", ua.StatusBadSecurityModeRejected, err)
	}
	if serverChannel.activeInstance != nil {
		t.Fatalf("expected active instance to remain nil after mode rejection")
	}
	if len(serverChannel.instances) != 0 {
		t.Fatalf("expected no registered channel instances after mode rejection, got %d", len(serverChannel.instances))
	}
	if serverChannel.openingInstance == nil || serverChannel.openingInstance.state != channelOpening {
		t.Fatalf("expected opening instance to remain in opening state after mode rejection")
	}
}

func TestCloseSecureChannelVerifyAndDecrypt(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		mode   ua.MessageSecurityMode
		keyLen int
	}{
		{name: "basic128rsa15-sign", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic128rsa15-signandencrypt", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256-sign", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256-signandencrypt", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256sha256-sign", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSign, keyLen: 4096},
		{name: "basic256sha256-signandencrypt", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 4096},
		{name: "aes128-sha256-rsaoaep-sign", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSign, keyLen: 4096},
		{name: "aes128-sha256-rsaoaep-signandencrypt", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 4096},
		{name: "aes256-sha256-rsapss-sign", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSign, keyLen: 4096},
		{name: "aes256-sha256-rsapss-signandencrypt", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			senderAlgo, receiverAlgo := newSymmetricTestAlgorithms(t, tt.uri, tt.keyLen)
			sender := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
				},
			}
			receiver := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
				},
			}
			senderInstance := &channelInstance{
				sc:              sender,
				algo:            senderAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}
			receiverInstance := &channelInstance{
				sc:              receiver,
				algo:            receiverAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}

			msg := senderInstance.newMessage(
				&ua.CloseSecureChannelRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           time.Date(2018, time.August, 10, 23, 0, 0, 0, time.UTC),
						RequestHandle:       1,
						AdditionalHeader:    ua.NewExtensionObject(nil),
					},
				},
				id.CloseSecureChannelRequest_Encoding_DefaultBinary,
				1,
			)

			raw, err := msg.Encode()
			require.NoError(t, err)
			expected := bytes.Clone(raw[12+msg.SymmetricSecurityHeader.Len():])

			cipher, err := senderInstance.signAndEncrypt(msg, raw)
			require.NoError(t, err)

			chunk := new(MessageChunk)
			_, err = chunk.Decode(cipher)
			require.NoError(t, err)

			plain, err := receiverInstance.verifyAndDecrypt(chunk, cipher)
			require.NoError(t, err)

			require.Equal(t, expected, plain)
		})
	}
}

func TestCreateSessionRequestVerifyAndDecrypt(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		mode   ua.MessageSecurityMode
		keyLen int
	}{
		{name: "basic128rsa15-sign", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic128rsa15-signandencrypt", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256-sign", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256-signandencrypt", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256sha256-sign", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256sha256-signandencrypt", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-sign", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-signandencrypt", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes256-sha256-rsapss-sign", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes256-sha256-rsapss-signandencrypt", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			senderAlgo, receiverAlgo := newSymmetricTestAlgorithms(t, tt.uri, tt.keyLen)
			sender := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
					Certificate:       bytes.Repeat([]byte{0x42}, 512),
				},
			}
			receiver := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
				},
			}
			senderInstance := &channelInstance{
				sc:              sender,
				algo:            senderAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}
			receiverInstance := &channelInstance{
				sc:              receiver,
				algo:            receiverAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}

			msg := senderInstance.newMessage(
				&ua.CreateSessionRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           time.Date(2018, time.August, 10, 23, 0, 0, 0, time.UTC),
						RequestHandle:       1,
						AdditionalHeader:    ua.NewExtensionObject(nil),
					},
					ClientDescription: &ua.ApplicationDescription{
						ApplicationURI: "urn:gopcua:test:client",
						ApplicationName: &ua.LocalizedText{
							Text: "gopcua test client",
						},
					},
					EndpointURL:             "opc.tcp://localhost:4840",
					SessionName:             "gopcua-test",
					ClientNonce:             bytes.Repeat([]byte{0x11}, 32),
					ClientCertificate:       bytes.Repeat([]byte{0x22}, 512),
					RequestedSessionTimeout: 60000,
				},
				id.CreateSessionRequest_Encoding_DefaultBinary,
				1,
			)

			raw, err := msg.Encode()
			require.NoError(t, err)
			expected := bytes.Clone(raw[12+msg.SymmetricSecurityHeader.Len():])

			cipher, err := senderInstance.signAndEncrypt(msg, raw)
			require.NoError(t, err)

			chunk := new(MessageChunk)
			_, err = chunk.Decode(cipher)
			require.NoError(t, err)

			plain, err := receiverInstance.verifyAndDecrypt(chunk, cipher)
			require.NoError(t, err)

			require.Equal(t, expected, plain)
		})
	}
}

func TestCreateSessionRequestChunkedRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		mode   ua.MessageSecurityMode
		keyLen int
	}{
		{name: "basic128rsa15-sign", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic128rsa15-signandencrypt", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256-sign", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256-signandencrypt", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256sha256-sign", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256sha256-signandencrypt", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-sign", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-signandencrypt", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes256-sha256-rsapss-sign", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes256-sha256-rsapss-signandencrypt", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			senderAlgo, receiverAlgo := newSymmetricTestAlgorithms(t, tt.uri, tt.keyLen)

			sender := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
					Certificate:       bytes.Repeat([]byte{0x42}, 512),
				},
				c: &uacp.Conn{},
			}
			receiver := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
				},
				c: &uacp.Conn{},
			}

			senderInstance := &channelInstance{
				sc:              sender,
				algo:            senderAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}
			receiverInstance := &channelInstance{
				sc:              receiver,
				algo:            receiverAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}

			senderInstance.maxBodySize = 128

			msg := senderInstance.newMessage(
				&ua.CreateSessionRequest{
					RequestHeader: &ua.RequestHeader{
						AuthenticationToken: ua.NewTwoByteNodeID(0),
						Timestamp:           time.Date(2018, time.August, 10, 23, 0, 0, 0, time.UTC),
						RequestHandle:       1,
						AdditionalHeader:    ua.NewExtensionObject(nil),
					},
					ClientDescription: &ua.ApplicationDescription{
						ApplicationURI: "urn:gopcua:test:client",
						ProductURI:     "urn:gopcua:test",
						ApplicationName: &ua.LocalizedText{
							Text: "gopcua test client",
						},
						ApplicationType: ua.ApplicationTypeClient,
					},
					EndpointURL:             "opc.tcp://localhost:4840",
					SessionName:             "gopcua-test",
					ClientNonce:             bytes.Repeat([]byte{0x11}, 32),
					ClientCertificate:       bytes.Repeat([]byte{0x22}, 1800),
					RequestedSessionTimeout: 60000,
					MaxResponseMessageSize:  math.MaxUint32,
				},
				id.CreateSessionRequest_Encoding_DefaultBinary,
				1,
			)

			raw, err := msg.Encode()
			require.NoError(t, err)
			expected := bytes.Clone(raw[12+msg.SymmetricSecurityHeader.Len()+8:])

			chunks, err := msg.EncodeChunks(senderInstance.maxBodySize)
			require.NoError(t, err)
			require.Greater(t, len(chunks), 1)

			decrypted := make([]*MessageChunk, 0, len(chunks))
			for i, chunk := range chunks {
				if i > 0 {
					number := senderInstance.nextSequenceNumber()
					binary.LittleEndian.PutUint32(chunk[16:], number)
				}

				cipher, err := senderInstance.signAndEncrypt(msg, chunk)
				require.NoError(t, err)

				m := new(MessageChunk)
				_, err = m.Decode(cipher)
				require.NoError(t, err)

				plain, err := receiverInstance.verifyAndDecrypt(m, cipher)
				require.NoError(t, err)

				m.Data = plain
				m.SequenceHeader = new(SequenceHeader)
				n, err := m.SequenceHeader.Decode(m.Data)
				require.NoError(t, err)
				m.Data = m.Data[n:]

				decrypted = append(decrypted, m)
			}

			merged, err := mergeChunks(decrypted)
			require.NoError(t, err)
			require.Equal(t, expected, merged)

			typeID, body, err := ua.DecodeService(merged)
			require.NoError(t, err)
			require.Equal(t, uint16(id.CreateSessionRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
			require.IsType(t, &ua.CreateSessionRequest{}, body)
		})
	}
}

func TestChannelInstanceUsesNegotiatedSecuritySettings(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		mode ua.MessageSecurityMode
	}{
		{name: "sign", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSign},
		{name: "sign-and-encrypt", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			senderAlgo, receiverAlgo := newSymmetricTestAlgorithms(t, tt.uri, 2048)

			sender := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
				},
				c: &uacp.Conn{},
			}
			receiver := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
				},
				c: &uacp.Conn{},
			}

			senderInstance := newChannelInstance(sender)
			senderInstance.algo = senderAlgo
			senderInstance.securityTokenID = 1
			senderInstance.secureChannelID = 1

			receiverInstance := newChannelInstance(receiver)
			receiverInstance.algo = receiverAlgo
			receiverInstance.securityTokenID = 1
			receiverInstance.secureChannelID = 1

			msg, err := senderInstance.newRequestMessage(
				&ua.ReadRequest{},
				1,
				nil,
				0,
			)
			require.NoError(t, err)

			raw, err := msg.Encode()
			require.NoError(t, err)
			expected := bytes.Clone(raw[12+msg.SymmetricSecurityHeader.Len()+8:])

			// The negotiated settings belong to the channel instance and must
			// remain effective even if the parent secure channel config changes.
			sender.cfg.SecurityMode = ua.MessageSecurityModeNone
			sender.cfg.SecurityPolicyURI = ua.SecurityPolicyURINone
			receiver.cfg.SecurityMode = ua.MessageSecurityModeNone
			receiver.cfg.SecurityPolicyURI = ua.SecurityPolicyURINone

			cipher, err := senderInstance.signAndEncrypt(msg, raw)
			require.NoError(t, err)

			chunk := new(MessageChunk)
			_, err = chunk.Decode(cipher)
			require.NoError(t, err)

			plain, err := receiverInstance.verifyAndDecrypt(chunk, cipher)
			require.NoError(t, err)
			require.Equal(t, expected, plain[8:])

			typeID, body, err := ua.DecodeService(plain[8:])
			require.NoError(t, err)
			require.Equal(t, uint16(id.ReadRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
			require.IsType(t, &ua.ReadRequest{}, body)
		})
	}
}

func TestServerReceivesCreateSessionRequestOverSecureChannel(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		mode ua.MessageSecurityMode
	}{
		{name: "basic128rsa15-sign", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSign},
		{name: "basic128rsa15-sign-and-encrypt", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSignAndEncrypt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			serverCertPEM, serverKeyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
			require.NoError(t, err)
			serverCertBlock, _ := pem.Decode(serverCertPEM)
			serverCert, err := x509.ParseCertificate(serverCertBlock.Bytes)
			require.NoError(t, err)
			serverKeyBlock, _ := pem.Decode(serverKeyPEM)
			serverKey, err := x509.ParsePKCS1PrivateKey(serverKeyBlock.Bytes)
			require.NoError(t, err)

			clientCertPEM, clientKeyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
			require.NoError(t, err)
			clientCertBlock, _ := pem.Decode(clientCertPEM)
			clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
			require.NoError(t, err)
			clientKeyBlock, _ := pem.Decode(clientKeyPEM)
			clientKey, err := x509.ParsePKCS1PrivateKey(clientKeyBlock.Bytes)
			require.NoError(t, err)

			listener, err := uacp.Listen(ctx, "opc.tcp://localhost:0", nil)
			require.NoError(t, err)
			defer listener.Close()
			endpoint := fmt.Sprintf("opc.tcp://%s", listener.Addr().String())

			serverErrCh := make(chan error, 1)
			serverMsgCh := make(chan *MessageBody, 1)
			go func() {
				conn, err := listener.Accept(ctx)
				if err != nil {
					serverErrCh <- err
					return
				}

				cfg := &Config{
					SecurityPolicyURI: ua.SecurityPolicyURINone,
					SecurityMode:      ua.MessageSecurityModeNone,
					Certificate:       serverCert.Raw,
					LocalKey:          serverKey,
					RequestTimeout:    2 * time.Second,
					Lifetime:          uint32((time.Hour) / time.Millisecond),
				}
				sc, err := NewServerSecureChannel(endpoint, conn, cfg, serverErrCh, 1, 1, 1)
				if err != nil {
					serverErrCh <- err
					return
				}

				for {
					msg := sc.Receive(ctx)
					if msg.Err != nil {
						serverErrCh <- msg.Err
						return
					}
					if msg.Request() == nil {
						continue
					}
					serverMsgCh <- msg
					return
				}
			}()

			conn, err := uacp.Dial(ctx, endpoint)
			require.NoError(t, err)

			clientErrCh := make(chan error, 1)
			clientCfg := &Config{
				SecurityPolicyURI: tt.uri,
				SecurityMode:      tt.mode,
				Certificate:       clientCert.Raw,
				LocalKey:          clientKey,
				RemoteCertificate: serverCert.Raw,
				Thumbprint:        uapolicy.Thumbprint(serverCert.Raw),
				RequestTimeout:    2 * time.Second,
				Lifetime:          uint32((time.Hour) / time.Millisecond),
			}
			clientSC, err := NewSecureChannel(endpoint, conn, clientCfg, clientErrCh)
			require.NoError(t, err)
			defer clientSC.Close()

			if err := clientSC.Open(ctx); err != nil {
				select {
				case serverErr := <-serverErrCh:
					t.Fatalf("open failed: %v (server err: %v)", err, serverErr)
				case clientErr := <-clientErrCh:
					t.Fatalf("open failed: %v (client err: %v)", err, clientErr)
				default:
					t.Fatalf("open failed: %v", err)
				}
			}
			require.NoError(t, clientSC.SendRequest(ctx, &ua.CreateSessionRequest{
				ClientDescription: &ua.ApplicationDescription{
					ApplicationURI:  "urn:gopcua:test:client",
					ProductURI:      "urn:gopcua:test",
					ApplicationName: ua.NewLocalizedText("gopcua test client"),
					ApplicationType: ua.ApplicationTypeClient,
				},
				EndpointURL:             endpoint,
				SessionName:             "gopcua-test",
				ClientNonce:             bytes.Repeat([]byte{0x11}, 32),
				ClientCertificate:       clientCert.Raw,
				RequestedSessionTimeout: float64((20 * time.Minute) / time.Millisecond),
			}, nil, nil))

			select {
			case err := <-serverErrCh:
				require.NoError(t, err)
			case msg := <-serverMsgCh:
				require.IsType(t, &ua.CreateSessionRequest{}, msg.Request())
			case <-ctx.Done():
				t.Fatalf("timed out waiting for server to decode CreateSessionRequest: %v", ctx.Err())
			}
		})
	}
}

func TestActivateSessionRequestMessageDecodes(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		mode   ua.MessageSecurityMode
		keyLen int
	}{
		{name: "basic128rsa15-sign", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic128rsa15-signandencrypt", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256-sign", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256-signandencrypt", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256sha256-sign", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256sha256-signandencrypt", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-sign", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-signandencrypt", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes256-sha256-rsapss-sign", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes256-sha256-rsapss-signandencrypt", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCertPEM, _, err := uatest.GenerateCert("localhost", tt.keyLen, 24*time.Hour)
			require.NoError(t, err)
			serverBlock, _ := pem.Decode(serverCertPEM)
			serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
			require.NoError(t, err)

			clientCertPEM, clientKeyPEM, err := uatest.GenerateCert("localhost", tt.keyLen, 24*time.Hour)
			require.NoError(t, err)
			clientKeyBlock, _ := pem.Decode(clientKeyPEM)
			clientKey, err := x509.ParsePKCS1PrivateKey(clientKeyBlock.Bytes)
			require.NoError(t, err)
			clientCertBlock, _ := pem.Decode(clientCertPEM)
			clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
			require.NoError(t, err)

			sc := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
					Certificate:       clientCert.Raw,
					LocalKey:          clientKey,
				},
			}
			sig, sigAlg, err := sc.NewSessionSignature(serverCert.Raw, bytes.Repeat([]byte{0x33}, 32))
			require.NoError(t, err)

			instance := &channelInstance{
				sc:              sc,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}
			msg, err := instance.newRequestMessage(
				&ua.ActivateSessionRequest{
					ClientSignature: &ua.SignatureData{
						Algorithm: sigAlg,
						Signature: sig,
					},
					ClientSoftwareCertificates: nil,
					LocaleIDs:                  []string{"en-us"},
					UserIdentityToken:          ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}),
					UserTokenSignature:         &ua.SignatureData{},
				},
				1,
				ua.NewTwoByteNodeID(0),
				0,
			)
			require.NoError(t, err)

			raw, err := msg.Encode()
			require.NoError(t, err)

			typeID, body, err := ua.DecodeService(raw[12+msg.SymmetricSecurityHeader.Len()+8:])
			require.NoError(t, err)
			require.Equal(t, uint16(id.ActivateSessionRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
			require.IsType(t, &ua.ActivateSessionRequest{}, body)
		})
	}
}

func TestOpenSecureChannelRequestMessageDecodes(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		mode ua.MessageSecurityMode
	}{
		{name: "basic128rsa15-sign", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSign},
		{name: "basic128rsa15-sign-and-encrypt", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSignAndEncrypt},
		{name: "basic256sha256-sign", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSign},
		{name: "basic256sha256-sign-and-encrypt", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCertPEM, serverKeyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
			require.NoError(t, err)
			serverCertBlock, _ := pem.Decode(serverCertPEM)
			serverCert, err := x509.ParseCertificate(serverCertBlock.Bytes)
			require.NoError(t, err)
			serverKeyBlock, _ := pem.Decode(serverKeyPEM)
			serverKey, err := x509.ParsePKCS1PrivateKey(serverKeyBlock.Bytes)
			require.NoError(t, err)

			clientCertPEM, clientKeyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
			require.NoError(t, err)
			clientCertBlock, _ := pem.Decode(clientCertPEM)
			clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
			require.NoError(t, err)
			clientKeyBlock, _ := pem.Decode(clientKeyPEM)
			clientKey, err := x509.ParsePKCS1PrivateKey(clientKeyBlock.Bytes)
			require.NoError(t, err)

			senderAlgo, err := uapolicy.Asymmetric(tt.uri, clientKey, serverCert.PublicKey.(*rsa.PublicKey))
			require.NoError(t, err)
			receiverAlgo, err := uapolicy.Asymmetric(tt.uri, serverKey, clientCert.PublicKey.(*rsa.PublicKey))
			require.NoError(t, err)

			sender := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
					Certificate:       clientCert.Raw,
					LocalKey:          clientKey,
					Thumbprint:        uapolicy.Thumbprint(serverCert.Raw),
				},
			}
			receiver := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
					Certificate:       serverCert.Raw,
					LocalKey:          serverKey,
				},
			}

			senderInstance := newChannelInstance(sender)
			senderInstance.algo = senderAlgo
			receiverInstance := newChannelInstance(receiver)
			receiverInstance.algo = receiverAlgo

			nonce, err := senderAlgo.MakeNonce()
			require.NoError(t, err)

			msg, err := senderInstance.newRequestMessage(
				&ua.OpenSecureChannelRequest{
					ClientProtocolVersion: 0,
					RequestType:           ua.SecurityTokenRequestTypeIssue,
					SecurityMode:          tt.mode,
					ClientNonce:           nonce,
					RequestedLifetime:     uint32((time.Hour) / time.Millisecond),
				},
				1,
				nil,
				0,
			)
			require.NoError(t, err)

			raw, err := msg.Encode()
			require.NoError(t, err)

			typeID, body, err := ua.DecodeService(raw[12+msg.AsymmetricSecurityHeader.Len()+8:])
			require.NoError(t, err)
			require.Equal(t, uint16(id.OpenSecureChannelRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
			require.IsType(t, &ua.OpenSecureChannelRequest{}, body)

			cipher, err := senderInstance.signAndEncrypt(msg, raw)
			require.NoError(t, err)

			chunk := new(MessageChunk)
			_, err = chunk.Decode(cipher)
			require.NoError(t, err)

			plain, err := receiverInstance.verifyAndDecrypt(chunk, cipher)
			require.NoError(t, err)
			require.Equal(t, raw[12+msg.AsymmetricSecurityHeader.Len():], plain)

			typeID, body, err = ua.DecodeService(plain[8:])
			require.NoError(t, err)
			require.Equal(t, uint16(id.OpenSecureChannelRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
			require.IsType(t, &ua.OpenSecureChannelRequest{}, body)
		})
	}
}

func TestOpenSecureChannelRequestDecodesBeforeSecurityModeNegotiation(t *testing.T) {
	serverCertPEM, serverKeyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
	require.NoError(t, err)
	serverCertBlock, _ := pem.Decode(serverCertPEM)
	serverCert, err := x509.ParseCertificate(serverCertBlock.Bytes)
	require.NoError(t, err)
	serverKeyBlock, _ := pem.Decode(serverKeyPEM)
	serverKey, err := x509.ParsePKCS1PrivateKey(serverKeyBlock.Bytes)
	require.NoError(t, err)

	clientCertPEM, clientKeyPEM, err := uatest.GenerateCert("localhost", 2048, 24*time.Hour)
	require.NoError(t, err)
	clientCertBlock, _ := pem.Decode(clientCertPEM)
	clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
	require.NoError(t, err)
	clientKeyBlock, _ := pem.Decode(clientKeyPEM)
	clientKey, err := x509.ParsePKCS1PrivateKey(clientKeyBlock.Bytes)
	require.NoError(t, err)

	senderAlgo, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic128Rsa15, clientKey, serverCert.PublicKey.(*rsa.PublicKey))
	require.NoError(t, err)
	receiverAlgo, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic128Rsa15, serverKey, clientCert.PublicKey.(*rsa.PublicKey))
	require.NoError(t, err)

	sender := &SecureChannel{
		cfg: &Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic128Rsa15,
			SecurityMode:      ua.MessageSecurityModeSign,
			Certificate:       clientCert.Raw,
			LocalKey:          clientKey,
			Thumbprint:        uapolicy.Thumbprint(serverCert.Raw),
		},
	}
	receiver := &SecureChannel{
		cfg: &Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic128Rsa15,
			SecurityMode:      ua.MessageSecurityModeNone,
			Certificate:       serverCert.Raw,
			LocalKey:          serverKey,
		},
	}

	senderInstance := newChannelInstance(sender)
	senderInstance.algo = senderAlgo
	receiverInstance := newChannelInstance(receiver)
	receiverInstance.algo = receiverAlgo

	nonce, err := senderAlgo.MakeNonce()
	require.NoError(t, err)

	msg, err := senderInstance.newRequestMessage(
		&ua.OpenSecureChannelRequest{
			ClientProtocolVersion: 0,
			RequestType:           ua.SecurityTokenRequestTypeIssue,
			SecurityMode:          ua.MessageSecurityModeSign,
			ClientNonce:           nonce,
			RequestedLifetime:     uint32((time.Hour) / time.Millisecond),
		},
		1,
		nil,
		0,
	)
	require.NoError(t, err)

	raw, err := msg.Encode()
	require.NoError(t, err)
	cipher, err := senderInstance.signAndEncrypt(msg, raw)
	require.NoError(t, err)

	chunk := new(MessageChunk)
	_, err = chunk.Decode(cipher)
	require.NoError(t, err)

	plain, err := receiverInstance.verifyAndDecrypt(chunk, cipher)
	require.NoError(t, err)

	typeID, body, err := ua.DecodeService(plain[8:])
	require.NoError(t, err)
	require.Equal(t, uint16(id.OpenSecureChannelRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
	require.IsType(t, &ua.OpenSecureChannelRequest{}, body)
}

func TestCreateSessionRequestMessageDecodes(t *testing.T) {
	instance := &channelInstance{
		sc: &SecureChannel{
			cfg: &Config{},
			time: func() time.Time {
				return time.Date(2019, 1, 1, 12, 13, 14, 0, time.UTC)
			},
		},
		sequenceNumber:  0,
		securityTokenID: 1,
		secureChannelID: 1,
	}

	msg, err := instance.newRequestMessage(
		&ua.CreateSessionRequest{
			ClientDescription: &ua.ApplicationDescription{
				ApplicationURI: "urn:gopcua:client",
				ProductURI:     "urn:gopcua",
				ApplicationName: &ua.LocalizedText{
					Text: "gopcua - OPC UA implementation in Go",
				},
				ApplicationType: ua.ApplicationTypeClient,
			},
			EndpointURL:             "opc.tcp://localhost:4840",
			SessionName:             "gopcua-test",
			ClientNonce:             bytes.Repeat([]byte{0x11}, 32),
			ClientCertificate:       bytes.Repeat([]byte{0x22}, 512),
			RequestedSessionTimeout: float64((20 * time.Minute) / time.Millisecond),
		},
		1,
		nil,
		0,
	)
	require.NoError(t, err)

	raw, err := msg.Encode()
	require.NoError(t, err)

	typeID, body, err := ua.DecodeService(raw[12+msg.SymmetricSecurityHeader.Len()+8:])
	require.NoError(t, err)
	require.Equal(t, uint16(id.CreateSessionRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
	require.IsType(t, &ua.CreateSessionRequest{}, body)
}

func TestActivateSessionRequestVerifyAndDecrypt(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		mode   ua.MessageSecurityMode
		keyLen int
	}{
		{name: "basic128rsa15-sign", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic128rsa15-signandencrypt", uri: ua.SecurityPolicyURIBasic128Rsa15, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256-sign", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256-signandencrypt", uri: ua.SecurityPolicyURIBasic256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "basic256sha256-sign", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "basic256sha256-signandencrypt", uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-sign", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes128-sha256-rsaoaep-signandencrypt", uri: ua.SecurityPolicyURIAes128Sha256RsaOaep, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
		{name: "aes256-sha256-rsapss-sign", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSign, keyLen: 2048},
		{name: "aes256-sha256-rsapss-signandencrypt", uri: ua.SecurityPolicyURIAes256Sha256RsaPss, mode: ua.MessageSecurityModeSignAndEncrypt, keyLen: 2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			senderAlgo, receiverAlgo := newSymmetricTestAlgorithms(t, tt.uri, tt.keyLen)

			serverCertPEM, _, err := uatest.GenerateCert("localhost", tt.keyLen, 24*time.Hour)
			require.NoError(t, err)
			serverBlock, _ := pem.Decode(serverCertPEM)
			serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
			require.NoError(t, err)

			clientCertPEM, clientKeyPEM, err := uatest.GenerateCert("localhost", tt.keyLen, 24*time.Hour)
			require.NoError(t, err)
			clientKeyBlock, _ := pem.Decode(clientKeyPEM)
			clientKey, err := x509.ParsePKCS1PrivateKey(clientKeyBlock.Bytes)
			require.NoError(t, err)
			clientCertBlock, _ := pem.Decode(clientCertPEM)
			clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
			require.NoError(t, err)

			sender := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
					Certificate:       clientCert.Raw,
					LocalKey:          clientKey,
				},
			}
			receiver := &SecureChannel{
				cfg: &Config{
					SecurityPolicyURI: tt.uri,
					SecurityMode:      tt.mode,
				},
			}
			senderInstance := &channelInstance{
				sc:              sender,
				algo:            senderAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}
			receiverInstance := &channelInstance{
				sc:              receiver,
				algo:            receiverAlgo,
				sequenceNumber:  0,
				securityTokenID: 1,
				secureChannelID: 1,
			}

			sig, sigAlg, err := sender.NewSessionSignature(serverCert.Raw, bytes.Repeat([]byte{0x33}, 32))
			require.NoError(t, err)

			msg, err := senderInstance.newRequestMessage(
				&ua.ActivateSessionRequest{
					ClientSignature: &ua.SignatureData{
						Algorithm: sigAlg,
						Signature: sig,
					},
					ClientSoftwareCertificates: nil,
					LocaleIDs:                  []string{"en-us"},
					UserIdentityToken:          ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}),
					UserTokenSignature:         &ua.SignatureData{},
				},
				1,
				ua.NewTwoByteNodeID(0),
				0,
			)
			require.NoError(t, err)

			raw, err := msg.Encode()
			require.NoError(t, err)
			expected := bytes.Clone(raw[12+msg.SymmetricSecurityHeader.Len():])

			cipher, err := senderInstance.signAndEncrypt(msg, raw)
			require.NoError(t, err)

			chunk := new(MessageChunk)
			_, err = chunk.Decode(cipher)
			require.NoError(t, err)

			plain, err := receiverInstance.verifyAndDecrypt(chunk, cipher)
			require.NoError(t, err)
			require.Equal(t, expected, plain)

			chunk.Data = plain
			chunk.SequenceHeader = new(SequenceHeader)
			n, err := chunk.SequenceHeader.Decode(chunk.Data)
			require.NoError(t, err)

			typeID, body, err := ua.DecodeService(chunk.Data[n:])
			require.NoError(t, err)
			require.Equal(t, uint16(id.ActivateSessionRequest_Encoding_DefaultBinary), uint16(typeID.NodeID.IntID()))
			require.IsType(t, &ua.ActivateSessionRequest{}, body)
		})
	}
}

func TestSignAndEncryptVerifyAndDecrypt(t *testing.T) {
	buildSecPolicy := func(bits int, uri string) *uapolicy.EncryptionAlgorithm {
		t.Helper()

		certPEM, keyPEM, err := uatest.GenerateCert("localhost", bits, 24*time.Hour)
		require.NoError(t, err)

		block, _ := pem.Decode(keyPEM)
		pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		require.NoError(t, err)

		certblock, _ := pem.Decode(certPEM)
		remoteX509Cert, err := x509.ParseCertificate(certblock.Bytes)
		require.NoError(t, err)

		remoteKey := remoteX509Cert.PublicKey.(*rsa.PublicKey)
		alg, _ := uapolicy.Asymmetric(uri, pk, remoteKey)
		return alg
	}

	getConfig := func(uri string) *Config {
		t.Helper()

		if uri == ua.SecurityPolicyURINone {
			return &Config{SecurityMode: ua.MessageSecurityModeNone}
		}
		return &Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt}
	}

	tests := []struct {
		name string
		c    *channelInstance
		m    *Message
		b    []byte
	}{}

	for _, uri := range ua.SecurityPolicyURIs {
		for i, keyLength := range []int{2048, 4096} {
			if i == 1 && (uri == ua.SecurityPolicyURIBasic128Rsa15 || uri == ua.SecurityPolicyURIBasic256) {
				continue
			}
			tests = append(tests, struct {
				name string
				c    *channelInstance
				m    *Message
				b    []byte
			}{fmt.Sprintf("encrypt/decrypt: bits: %d uri: %s", keyLength, uri),
				&channelInstance{
					sc:   &SecureChannel{cfg: getConfig(uri)},
					algo: buildSecPolicy(keyLength, uri),
				},
				&Message{
					MessageHeader: &MessageHeader{
						Header: &Header{
							MessageType: MessageTypeOpenSecureChannel,
							ChunkType:   ChunkTypeFinal,
						},
						AsymmetricSecurityHeader: &AsymmetricSecurityHeader{
							SecurityPolicyURI: "http://gopcua.example/OPCUA/SecurityPolicy#Foo",
						},
						SequenceHeader: &SequenceHeader{
							SequenceNumber: 1,
							RequestID:      1,
						},
					},
				},
				[]byte{ // OpenSecureChannelRequest
					// Message Header
					// MessageType: OPN
					0x4f, 0x50, 0x4e,
					// Chunk Type: Final
					0x46,
					// MessageSize: 131
					0x8E, 0x00, 0x00, 0x00,
					// SecureChannelID: 0
					0x00, 0x00, 0x00, 0x00,
					// AsymmetricSecurityHeader
					// SecurityPolicyURILength
					0x2e, 0x00, 0x00, 0x00,
					// SecurityPolicyURI
					0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x67,
					0x6f, 0x70, 0x63, 0x75, 0x61, 0x2e, 0x65, 0x78,
					0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x4f, 0x50,
					0x43, 0x55, 0x41, 0x2f, 0x53, 0x65, 0x63, 0x75,
					0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69,
					0x63, 0x79, 0x23, 0x46, 0x6f, 0x6f,
					// SenderCertificate
					0xff, 0xff, 0xff, 0xff,
					// ReceiverCertificateThumbprint
					0xff, 0xff, 0xff, 0xff,
					// Sequence Header
					// SequenceNumber
					0x01, 0x00, 0x00, 0x00,
					// RequestID
					0x01, 0x00, 0x00, 0x00,
					// TypeID
					0x01, 0x00, 0xbe, 0x01,

					// RequestHeader
					// - AuthenticationToken
					0x00, 0x00,
					// - Timestamp
					0x00, 0x98, 0x67, 0xdd, 0xfd, 0x30, 0xd4, 0x01,
					// - RequestHandle
					0x01, 0x00, 0x00, 0x00,
					// - ReturnDiagnostics
					0xff, 0x03, 0x00, 0x00,
					// - AuditEntry
					0xff, 0xff, 0xff, 0xff,
					// - TimeoutHint
					0x00, 0x00, 0x00, 0x00,
					// - AdditionalHeader
					//   - TypeID
					0x00, 0x00,
					//   - EncodingMask
					0x00,
					// ClientProtocolVersion
					0x00, 0x00, 0x00, 0x00,
					// SecurityTokenRequestType
					0x00, 0x00, 0x00, 0x00,
					// MessageSecurityMode
					0x01, 0x00, 0x00, 0x00,
					// ClientNonce
					0xff, 0xff, 0xff, 0xff,
					// RequestedLifetime
					0x80, 0x8d, 0x5b, 0x00,
				}})
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := tt.c.signAndEncrypt(tt.m, tt.b)
			require.NoError(t, err, "error: message encrypt")

			m := new(MessageChunk)
			_, err = m.Decode(cipher)
			require.NoError(t, err, "error: message decode")

			plain, err := tt.c.verifyAndDecrypt(m, cipher)
			require.NoError(t, err, "error: message decrypt")

			headerLength := 12 + m.AsymmetricSecurityHeader.Len()
			require.Equal(t, tt.b[headerLength:], plain, "header not equal")
		})
	}
}

func newSymmetricTestAlgorithms(t *testing.T, uri string, bits int) (*uapolicy.EncryptionAlgorithm, *uapolicy.EncryptionAlgorithm) {
	t.Helper()

	certPEM, keyPEM, err := uatest.GenerateCert("localhost", bits, 24*time.Hour)
	require.NoError(t, err)

	block, _ := pem.Decode(keyPEM)
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	certBlock, _ := pem.Decode(certPEM)
	remoteCert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)

	remoteKey := remoteCert.PublicKey.(*rsa.PublicKey)
	asym, err := uapolicy.Asymmetric(uri, pk, remoteKey)
	require.NoError(t, err)

	localNonce, err := asym.MakeNonce()
	require.NoError(t, err)
	remoteNonce, err := asym.MakeNonce()
	require.NoError(t, err)

	sender, err := uapolicy.Symmetric(uri, localNonce, remoteNonce)
	require.NoError(t, err)
	receiver, err := uapolicy.Symmetric(uri, remoteNonce, localNonce)
	require.NoError(t, err)
	return sender, receiver
}

func TestNewSecureChannel(t *testing.T) {
	t.Run("no connection", func(t *testing.T) {
		_, err := NewSecureChannel("", nil, nil, nil)
		require.ErrorContains(t, err, "no connection")
	})
	t.Run("no error channel", func(t *testing.T) {
		_, err := NewSecureChannel("", &uacp.Conn{}, nil, nil)
		require.ErrorContains(t, err, "no secure channel config")
	})
	t.Run("no config", func(t *testing.T) {
		_, err := NewSecureChannel("", &uacp.Conn{}, nil, make(chan error))
		require.ErrorContains(t, err, "no secure channel config")
	})
	t.Run("uri none, mode not none", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeSign}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid channel config: Security policy 'http://opcfoundation.org/UA/SecurityPolicy#None' cannot be used with 'MessageSecurityModeSign'")
	})
	t.Run("uri not none, mode none", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256, SecurityMode: ua.MessageSecurityModeNone}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid channel config: Security policy 'http://opcfoundation.org/UA/SecurityPolicy#Basic256' can only be used with 'MessageSecurityModeSign' or 'MessageSecurityModeSignAndEncrypt'")
	})
	t.Run("uri not none, security policy not none, mode invalid", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256, SecurityMode: ua.MessageSecurityModeInvalid}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid channel config: Security policy 'http://opcfoundation.org/UA/SecurityPolicy#Basic256' can only be used with 'MessageSecurityModeSign' or 'MessageSecurityModeSignAndEncrypt'")
	})
	t.Run("uri not none, local key missing", func(t *testing.T) {
		cfg := &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256, SecurityMode: ua.MessageSecurityModeSign}
		_, err := NewSecureChannel("", &uacp.Conn{}, cfg, make(chan error))
		require.ErrorContains(t, err, "invalid channel config: Security policy 'http://opcfoundation.org/UA/SecurityPolicy#Basic256' requires a private key")
	})
}
