package services

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
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

func resolveUserTokenSecurityPolicyURI(policy *ua.UserTokenPolicy, secureChannelPolicyURI string) (string, error) {
	if policy == nil {
		return "", ua.StatusBadIdentityTokenInvalid
	}

	policyURI := policy.SecurityPolicyURI
	if policyURI == "" {
		policyURI = secureChannelPolicyURI
	}

	if policyURI == "" {
		return "", ua.StatusBadIdentityTokenInvalid
	}
	if !slices.Contains(uapolicy.SupportedPolicies(), policyURI) {
		return "", ua.StatusBadIdentityTokenRejected
	}

	return policyURI, nil
}

func validateUserNameIdentityToken(token *ua.UserNameIdentityToken, endpoints []*ua.EndpointDescription, secureChannelPolicyURI string, privateKey *rsa.PrivateKey, serverNonce []byte) (string, error) {
	if token == nil {
		return "", ua.StatusBadIdentityTokenInvalid
	}

	policy, err := resolveUserTokenPolicy(token, endpoints)
	if err != nil {
		return "", err
	}

	policyURI, err := resolveUserTokenSecurityPolicyURI(policy, secureChannelPolicyURI)
	if err != nil {
		return "", err
	}

	if err := validateUserNameEncryptionAlgorithm(token, policyURI, privateKey); err != nil {
		return "", err
	}

	return decodeUserNamePassword(token, policyURI, privateKey, serverNonce)
}

func validateUserNameEncryptionAlgorithm(token *ua.UserNameIdentityToken, policyURI string, privateKey *rsa.PrivateKey) error {
	if token == nil {
		return ua.StatusBadIdentityTokenInvalid
	}

	if policyURI == ua.SecurityPolicyURINone {
		if token.EncryptionAlgorithm != "" {
			return ua.StatusBadIdentityTokenInvalid
		}
		return nil
	}

	if privateKey == nil {
		return ua.StatusBadIdentityTokenInvalid
	}

	algo, err := uapolicy.Asymmetric(policyURI, privateKey, nil)
	if err != nil {
		return ua.StatusBadIdentityTokenRejected
	}

	if token.EncryptionAlgorithm != algo.EncryptionURI() {
		return ua.StatusBadIdentityTokenInvalid
	}

	return nil
}

func authenticateUserIdentity(
	ctx context.Context,
	session types.Session,
	token any,
	endpoints []*ua.EndpointDescription,
	secureChannelPolicyURI string,
	privateKey *rsa.PrivateKey,
	serverNonce []byte,
	authenticator auth.UserNameAuthenticator,
) (*auth.AuthenticatedUser, error) {
	switch tok := token.(type) {
	case *ua.AnonymousIdentityToken:
		return nil, nil
	case *ua.UserNameIdentityToken:
		if authenticator == nil {
			return nil, ua.StatusBadIdentityTokenRejected
		}

		password, err := validateUserNameIdentityToken(tok, endpoints, secureChannelPolicyURI, privateKey, serverNonce)
		if err != nil {
			return nil, err
		}

		user, err := authenticator(ctx, &auth.UserNameAuthenticationRequest{
			SessionID:           session.ID(),
			AuthenticationToken: session.AuthTokenID(),
			UserName:            tok.UserName,
			Password:            password,
		})
		if err != nil {
			return nil, statusCodeForUserNameAuthenticatorError(err)
		}

		return user, nil
	default:
		return nil, ua.StatusBadIdentityTokenInvalid
	}
}

func statusCodeForUserNameAuthenticatorError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, auth.ErrInvalidCredentials):
		return ua.StatusBadIdentityTokenRejected
	case errors.Is(err, auth.ErrUnsupportedAuthentication):
		return ua.StatusBadIdentityTokenRejected
	case errors.Is(err, auth.ErrBackendUnavailable):
		return ua.StatusBadResourceUnavailable
	default:
		return ua.StatusBadInternalError
	}
}
