package services

import "github.com/gopcua/opcua/ua"

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
