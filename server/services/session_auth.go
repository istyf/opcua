package services

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
)

func decodeUserIdentityToken(token *ua.ExtensionObject) (any, error) {
	if token == nil || token.Value == nil {
		return nil, ua.StatusBadIdentityTokenInvalid
	}

	switch tok := token.Value.(type) {
	case *ua.AnonymousIdentityToken:
		if tok == nil {
			return nil, ua.StatusBadIdentityTokenInvalid
		}
		return tok, nil
	case *ua.UserNameIdentityToken:
		if tok == nil {
			return nil, ua.StatusBadIdentityTokenInvalid
		}
		return tok, nil
	case *ua.X509IdentityToken, *ua.IssuedIdentityToken:
		return nil, ua.StatusBadIdentityTokenRejected
	default:
		return nil, ua.StatusBadIdentityTokenInvalid
	}
}

func resolveUserTokenPolicy(token any, endpoints []*ua.EndpointDescription) (*ua.UserTokenPolicy, error) {
	var (
		policyID  string
		tokenType ua.UserTokenType
	)

	switch tok := token.(type) {
	case *ua.AnonymousIdentityToken:
		policyID = tok.PolicyID
		tokenType = ua.UserTokenTypeAnonymous
	case *ua.UserNameIdentityToken:
		policyID = tok.PolicyID
		tokenType = ua.UserTokenTypeUserName
	default:
		return nil, ua.StatusBadIdentityTokenInvalid
	}

	if policyID == "" {
		return nil, ua.StatusBadIdentityTokenInvalid
	}

	for _, ep := range endpoints {
		for _, policy := range ep.UserIdentityTokens {
			if policy.PolicyID != policyID {
				continue
			}
			if policy.TokenType != tokenType {
				return nil, ua.StatusBadIdentityTokenRejected
			}
			return policy, nil
		}
	}

	return nil, ua.StatusBadIdentityTokenRejected
}

func decodeUserNamePassword(token *ua.UserNameIdentityToken, policyURI string, privateKey *rsa.PrivateKey, serverNonce []byte) (string, error) {
	if token == nil {
		return "", ua.StatusBadIdentityTokenInvalid
	}

	if policyURI == ua.SecurityPolicyURINone {
		return string(token.Password), nil
	}

	if privateKey == nil {
		return "", ua.StatusBadIdentityTokenInvalid
	}

	algo, err := uapolicy.Asymmetric(policyURI, privateKey, nil)
	if err != nil {
		return "", ua.StatusBadIdentityTokenRejected
	}

	cleartext, err := algo.Decrypt(token.Password)
	if err != nil {
		return "", ua.StatusBadIdentityTokenInvalid
	}
	if len(cleartext) < 4 {
		return "", ua.StatusBadIdentityTokenInvalid
	}

	secretLen := int(binary.LittleEndian.Uint32(cleartext[:4]))
	secret := cleartext[4:]
	if len(secret) != secretLen || secretLen < len(serverNonce) {
		return "", ua.StatusBadIdentityTokenInvalid
	}

	passwordLen := secretLen - len(serverNonce)
	passwordBytes := secret[:passwordLen]
	nonce := secret[passwordLen:]
	if !bytes.Equal(nonce, serverNonce) {
		return "", ua.StatusBadNonceInvalid
	}

	return string(passwordBytes), nil
}
