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
