// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"context"
	"fmt"

	srvctx "github.com/gopcua/opcua/server/context"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

func (s *serverImpl) initHandlers() {
	// s.registerHandlerFunc(id.ServiceFault_Encoding_DefaultBinary, handleServiceFault)

	s.discoveryService = services.NewDiscoveryService(s)

	// SecureChannel service (handled in the uasc stack)
	// s.registerHandlerFunc(id.OpenSecureChannelRequest_Encoding_DefaultBinary, handleOpenSecureChannel)
	// s.registerHandlerFunc(id.CloseSecureChannelRequest_Encoding_DefaultBinary, handleCloseSecureChannel)

	s.attributeService = services.NewAttributeService(s)
	s.methodService = services.NewMethodService(s, s.Config().MethodCallMiddleware())
	s.nodeManagementService = services.NewNodeManagementService(s)
	s.queryService = services.NewQueryService(s)
	s.sessionService = services.NewSessionService(s, s.cfg.AdvertisedCertificate())
	s.viewService = services.NewViewService(s)

	s.SubscriptionService = services.NewSubscriptionService(s)
	s.MonitoredItemService = services.NewMonitoredItemService(s)
}

// This function allows you to overwrite a handler before you call start.
func (s *serverImpl) RegisterHandler(typeID int, h services.Handler) {
	_, ok := s.handlers[typeID]
	if !ok {
		s.handlers[typeID] = h
	}
}

func (s *serverImpl) handleService(ctx context.Context, sc *uasc.SecureChannel, reqID uint32, req ua.Request) {
	ualog.Debug(ctx, "handling service request", ualog.Any("request", req))

	var resp ua.Response
	var err error
	defer func() {
		if recovered := recover(); recovered != nil {
			resp = serviceFaultFromRecoveredPanic(ctx, recovered)
			err = nil
		}
		if resp == nil {
			return
		}

		sendErr := sc.SendResponseWithContext(ctx, reqID, resp)
		if sendErr != nil {
			ualog.Warn(ctx, "unable to send response", ualog.Err(sendErr))
		}
	}()

	typeID := int(ua.ServiceTypeID(req))
	h, ok := s.handlers[typeID]
	if ok {
		handlerContext := ctx

		if session := s.sb.Session(ctx, req.Header().AuthenticationToken); session != nil {
			handlerContext = srvctx.WithPreferedLocales(ctx, session.Locales())
		}

		resp, err = h(handlerContext, sc, req, reqID)
	} else {
		if typeID == 0 {
			ualog.Warn(ctx, "unknown (potentially non registered) service", ualog.Any("request", req))
		}
		err = ua.StatusBadServiceUnsupported
	}

	if err != nil {
		if statusCode, ok := err.(ua.StatusCode); ok {
			resp = &ua.ServiceFault{ResponseHeader: services.NewResponseHeader(0, statusCode)}
		} else {
			resp = &ua.ServiceFault{ResponseHeader: services.NewResponseHeader(0, ua.StatusBadUnexpectedError)}
		}
	}

	if resp == nil {
		return
	}
}

func serviceFaultFromRecoveredPanic(ctx context.Context, recovered any) ua.Response {
	ualog.Error(ctx, "recovered panic while handling service request",
		ualog.String("panic", fmt.Sprint(recovered)),
	)
	return &ua.ServiceFault{ResponseHeader: services.NewResponseHeader(0, ua.StatusBadUnexpectedError)}
}
