package server

import "github.com/gopcua/opcua/ua"

// SecurityPolicy identifies an OPC UA secure-channel security policy that can
// be enabled on the server.
type SecurityPolicy string

const (
	SecurityPolicyNone SecurityPolicy = SecurityPolicy(ua.SecurityPolicyURINone)
	// SecurityPolicyBasic128Rsa15 is kept for completeness but is intentionally
	// rejected by the server because the policy is deprecated.
	SecurityPolicyBasic128Rsa15       SecurityPolicy = SecurityPolicy(ua.SecurityPolicyURIBasic128Rsa15)
	SecurityPolicyBasic256            SecurityPolicy = SecurityPolicy(ua.SecurityPolicyURIBasic256)
	SecurityPolicyBasic256Sha256      SecurityPolicy = SecurityPolicy(ua.SecurityPolicyURIBasic256Sha256)
	SecurityPolicyAes128Sha256RsaOaep SecurityPolicy = SecurityPolicy(ua.SecurityPolicyURIAes128Sha256RsaOaep)
	SecurityPolicyAes256Sha256RsaPss  SecurityPolicy = SecurityPolicy(ua.SecurityPolicyURIAes256Sha256RsaPss)
)

func (p SecurityPolicy) URI() string {
	return string(p)
}
