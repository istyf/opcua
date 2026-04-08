package services

import (
	"context"
	"crypto/rand"
	"strings"
	"time"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

const (
	sessionNonceLength = 32
)

type SessionBroker interface {
	Endpoints() []*ua.EndpointDescription

	NewSession(timeout time.Duration, serverNonce []byte, remoteCert []byte) types.Session
	Session(ctx context.Context, hdr *ua.RequestHeader) types.Session
	CloseSession(ctx context.Context, authToken *ua.NodeID) error
}

// SessionService implements the Session Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6
type SessionService struct {
	srv        SessionBroker
	serverCert []byte
}

func NewSessionService(s SessionBroker, serverCert []byte) *SessionService {
	return &SessionService{
		srv:        s,
		serverCert: serverCert,
	}
}

var newSessionServiceLogAttribute = newServiceLogAttributeCreatorForSet("session")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.2
func (s *SessionService) CreateSession(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSessionServiceLogAttribute("create"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.CreateSessionRequest](r)
	if err != nil {
		return nil, err
	}

	requestedTimeout := time.Duration(req.RequestedSessionTimeout) * time.Millisecond
	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		ualog.Error(ctx, "failed to create session nonce", ualog.Err(err))
		return nil, ua.StatusBadInternalError
	}

	// New session
	sess := s.srv.NewSession(requestedTimeout, nonce, req.ClientCertificate)

	sig, alg, err := sc.NewSessionSignature(req.ClientCertificate, req.ClientNonce)
	if err != nil {
		ualog.Error(ctx, "failed to create session signature", ualog.Err(err))
		return nil, ua.StatusBadInternalError
	}

	matching_endpoints := make([]*ua.EndpointDescription, 0)
	reqTrimmedURL, _ := strings.CutSuffix(req.EndpointURL, "/")
	for _, ep := range s.srv.Endpoints() {
		epTrimmedURL, _ := strings.CutSuffix(ep.EndpointURL, "/")
		if epTrimmedURL == reqTrimmedURL {
			matching_endpoints = append(matching_endpoints, ep)
		}
	}

	response := &ua.CreateSessionResponse{
		ResponseHeader:        NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		SessionID:             sess.ID(),
		AuthenticationToken:   sess.AuthTokenID(),
		RevisedSessionTimeout: sess.TimeOutInMillis(),
		MaxRequestMessageSize: 0, // Not used
		ServerSignature: &ua.SignatureData{
			Signature: sig,
			Algorithm: alg,
		},
		ServerCertificate: s.serverCert,
		ServerNonce:       nonce,
		ServerEndpoints:   matching_endpoints,
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.3
func (s *SessionService) ActivateSession(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSessionServiceLogAttribute("activate"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.ActivateSessionRequest](r)
	if err != nil {
		return nil, err
	}

	sess := s.srv.Session(ctx, req.RequestHeader)
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	err = sc.VerifySessionSignature(sess.RemoteCertificate(), sess.ServerNonce(), req.ClientSignature.Signature)
	if err != nil {
		ualog.Error(ctx, "failed to verify session signature", ualog.Err(err))
		return nil, ua.StatusBadSecurityChecksFailed
	}

	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		ualog.Error(ctx, "failed to create session nonce", ualog.Err(err))
		return nil, ua.StatusBadInternalError
	}
	sess.SetServerNonce(nonce)
	sess.SetLocales(req.LocaleIDs)

	response := &ua.ActivateSessionResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		ServerNonce:    nonce,
		// Results:         []ua.StatusCode{},
		// DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.4
func (s *SessionService) CloseSession(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSessionServiceLogAttribute("close"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.CloseSessionRequest](r)
	if err != nil {
		return nil, err
	}

	err = s.srv.CloseSession(ctx, req.RequestHeader.AuthenticationToken)
	if err != nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	//TODO: deal with 'delete subscriptions' field in request
	response := &ua.CloseSessionResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.5
func (s *SessionService) Cancel(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSessionServiceLogAttribute("cancel"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.CancelRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}
