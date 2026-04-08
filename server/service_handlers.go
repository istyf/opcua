// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"context"

	"github.com/gopcua/opcua/id"
	srvctx "github.com/gopcua/opcua/server/context"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type Handler func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error)

func (s *serverImpl) initHandlers() {
	// s.registerHandlerFunc(id.ServiceFault_Encoding_DefaultBinary, handleServiceFault)

	discovery := services.NewDiscoveryService(s)
	s.RegisterHandler(id.FindServersRequest_Encoding_DefaultBinary, discovery.FindServers)
	s.RegisterHandler(id.FindServersOnNetworkRequest_Encoding_DefaultBinary, discovery.FindServersOnNetwork)
	s.RegisterHandler(id.GetEndpointsRequest_Encoding_DefaultBinary, discovery.GetEndpoints)
	s.RegisterHandler(id.RegisterServerRequest_Encoding_DefaultBinary, discovery.RegisterServer)
	s.RegisterHandler(id.RegisterServer2Request_Encoding_DefaultBinary, discovery.RegisterServer2)

	// SecureChannel service (handled in the uasc stack)
	// s.registerHandlerFunc(id.OpenSecureChannelRequest_Encoding_DefaultBinary, handleOpenSecureChannel)
	// s.registerHandlerFunc(id.CloseSecureChannelRequest_Encoding_DefaultBinary, handleCloseSecureChannel)

	session := services.NewSessionService(s, s.cfg.certificate)
	s.RegisterHandler(id.CreateSessionRequest_Encoding_DefaultBinary, session.CreateSession)
	s.RegisterHandler(id.ActivateSessionRequest_Encoding_DefaultBinary, session.ActivateSession)
	s.RegisterHandler(id.CloseSessionRequest_Encoding_DefaultBinary, session.CloseSession)
	s.RegisterHandler(id.CancelRequest_Encoding_DefaultBinary, session.Cancel)

	node := services.NewNodeManagementService(s)
	s.RegisterHandler(id.AddNodesRequest_Encoding_DefaultBinary, node.AddNodes)
	s.RegisterHandler(id.AddReferencesRequest_Encoding_DefaultBinary, node.AddReferences)
	s.RegisterHandler(id.DeleteNodesRequest_Encoding_DefaultBinary, node.DeleteNodes)
	s.RegisterHandler(id.DeleteReferencesRequest_Encoding_DefaultBinary, node.DeleteReferences)

	view := services.NewViewService(s)
	s.RegisterHandler(id.BrowseRequest_Encoding_DefaultBinary, view.Browse)
	s.RegisterHandler(id.BrowseNextRequest_Encoding_DefaultBinary, view.BrowseNext)
	s.RegisterHandler(id.TranslateBrowsePathsToNodeIDsRequest_Encoding_DefaultBinary, view.TranslateBrowsePathsToNodeIDs)
	s.RegisterHandler(id.RegisterNodesRequest_Encoding_DefaultBinary, view.RegisterNodes)
	s.RegisterHandler(id.UnregisterNodesRequest_Encoding_DefaultBinary, view.UnregisterNodes)

	query := services.NewQueryService(s)
	s.RegisterHandler(id.QueryFirstRequest_Encoding_DefaultBinary, query.QueryFirst)
	s.RegisterHandler(id.QueryNextRequest_Encoding_DefaultBinary, query.QueryNext)

	attr := services.NewAttributeService(s)
	s.RegisterHandler(id.ReadRequest_Encoding_DefaultBinary, attr.Read)
	s.RegisterHandler(id.HistoryReadRequest_Encoding_DefaultBinary, attr.HistoryRead)
	s.RegisterHandler(id.WriteRequest_Encoding_DefaultBinary, attr.Write)
	s.RegisterHandler(id.HistoryUpdateRequest_Encoding_DefaultBinary, attr.HistoryUpdate)

	method := services.NewMethodService(s, s.Config().MethodCallMiddleware())
	// s.registerHandler(id.CallMethodRequest_Encoding_DefaultBinary, method.CallMethod) // todo(fs): I think this is bogus
	s.RegisterHandler(id.CallRequest_Encoding_DefaultBinary, method.Call)

	sub := services.NewSubscriptionService(s)
	s.SubscriptionService = sub
	s.RegisterHandler(id.CreateSubscriptionRequest_Encoding_DefaultBinary, sub.CreateSubscription)
	s.RegisterHandler(id.ModifySubscriptionRequest_Encoding_DefaultBinary, sub.ModifySubscription)
	s.RegisterHandler(id.SetPublishingModeRequest_Encoding_DefaultBinary, sub.SetPublishingMode)
	s.RegisterHandler(id.PublishRequest_Encoding_DefaultBinary, sub.Publish)
	s.RegisterHandler(id.RepublishRequest_Encoding_DefaultBinary, sub.Republish)
	s.RegisterHandler(id.TransferSubscriptionsRequest_Encoding_DefaultBinary, sub.TransferSubscriptions)
	s.RegisterHandler(id.DeleteSubscriptionsRequest_Encoding_DefaultBinary, sub.DeleteSubscriptions)

	item := services.NewMonitoredItemService(sub)
	s.MonitoredItemService = item
	// s.registerHandler(id.MonitoredItemCreateRequest_Encoding_DefaultBinary, item.MonitoredItemCreate)
	s.RegisterHandler(id.CreateMonitoredItemsRequest_Encoding_DefaultBinary, item.CreateMonitoredItems)
	//s.RegisterHandler(id.CreateMonitoredItemsRequest_Encoding_DefaultBinary, s.CreateMonitoredItems)
	// s.registerHandler(id.MonitoredItemModifyRequest_Encoding_DefaultBinary, item.MonitoredItemModify)
	s.RegisterHandler(id.ModifyMonitoredItemsRequest_Encoding_DefaultBinary, item.ModifyMonitoredItems)
	s.RegisterHandler(id.SetMonitoringModeRequest_Encoding_DefaultBinary, item.SetMonitoringMode)
	s.RegisterHandler(id.SetTriggeringRequest_Encoding_DefaultBinary, item.SetTriggering)
	s.RegisterHandler(id.DeleteMonitoredItemsRequest_Encoding_DefaultBinary, item.DeleteMonitoredItems)
}

// This function allows you to overwrite a handler before you call start.
func (s *serverImpl) RegisterHandler(typeID uint16, h Handler) {
	_, ok := s.handlers[typeID]
	if !ok {
		s.handlers[typeID] = h
	}
}

func (s *serverImpl) handleService(ctx context.Context, sc *uasc.SecureChannel, reqID uint32, req ua.Request) {
	ualog.Debug(ctx, "handling service request", ualog.Any("request", req))

	var resp ua.Response
	var err error

	typeID := ua.ServiceTypeID(req)
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

	err = sc.SendResponseWithContext(ctx, reqID, resp)
	if err != nil {
		ualog.Warn(ctx, "unable to send response", ualog.Err(err))
	}
}
