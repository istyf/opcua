package services

import (
	"time"

	"github.com/gopcua/opcua/ua"
)

func NewResponseHeader(reqID uint32, statusCode ua.StatusCode) *ua.ResponseHeader {
	return &ua.ResponseHeader{
		Timestamp:          time.Now(),
		RequestHandle:      reqID,
		ServiceResult:      statusCode,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}

func serviceUnsupported(hdr *ua.RequestHeader) ua.Response {
	return &ua.ServiceFault{
		ResponseHeader: NewResponseHeader(hdr.RequestHandle, ua.StatusBadServiceUnsupported),
	}
}

func safeReq[T ua.Request](r ua.Request) (T, error) {
	var t T
	req, ok := r.(T)
	if !ok {
		//debug.Printf("expected %T, got %T", t, r)
		return t, ua.StatusBadRequestTypeInvalid
	}
	return req, nil
}

// func handleServiceFault(s Server, sc *uasc.SecureChannel, r ua.Request) (ua.Response, error) {
// 	debug.Printf("Handling %T", r)

// 	req, ok := r.(*ua.ServiceFault)
// 	if !ok {
// 		debug.Printf("handleServiceFault: Expected *ua.ServiceFault, got %T", r)
// 		return nil, ua.StatusBadRequestTypeInvalid
// 	}
// 	debug.Printf("Got ServiceFault: %s", req.ResponseHeader.ServiceResult)

// 	// No response required
// 	return nil, nil
// }
