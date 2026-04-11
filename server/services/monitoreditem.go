package services

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type MonitoredItemServiceBackend interface {
	HandlerRegistrator
	NamespaceProvider
	SessionProvider
	SubscriptionProvider
}

// MonitoredItemService implements the MonitoredItem Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12
type MonitoredItemService struct {
	backend MonitoredItemServiceBackend

	mu sync.Mutex

	// items tracked by ID
	items map[uint32]*MonitoredItem
	// items tracked by node
	nodes map[string][]*MonitoredItem
	// items tracked by subscription
	subs map[types.SubscriptionID][]*MonitoredItem

	previousID atomic.Uint32
}

func NewMonitoredItemService(b MonitoredItemServiceBackend) *MonitoredItemService {
	mis := &MonitoredItemService{
		backend:    b,
		items:      make(map[uint32]*MonitoredItem),
		nodes:      make(map[string][]*MonitoredItem),
		subs:       make(map[types.SubscriptionID][]*MonitoredItem),
		previousID: atomic.Uint32{},
	}

	// b.registerHandler(id.MonitoredItemCreateRequest_Encoding_DefaultBinary, mis.MonitoredItemCreate)
	b.RegisterHandler(id.CreateMonitoredItemsRequest_Encoding_DefaultBinary, mis.CreateMonitoredItems)
	// b.registerHandler(id.MonitoredItemModifyRequest_Encoding_DefaultBinary, mis.MonitoredItemModify)
	b.RegisterHandler(id.ModifyMonitoredItemsRequest_Encoding_DefaultBinary, mis.ModifyMonitoredItems)
	b.RegisterHandler(id.SetMonitoringModeRequest_Encoding_DefaultBinary, mis.SetMonitoringMode)
	b.RegisterHandler(id.SetTriggeringRequest_Encoding_DefaultBinary, mis.SetTriggering)
	b.RegisterHandler(id.DeleteMonitoredItemsRequest_Encoding_DefaultBinary, mis.DeleteMonitoredItems)

	return mis
}

var newMonitoredItemServiceLogAttribute = newServiceLogAttributeCreatorForSet("monitoreditem")

// function to get rid of all references to a specific Monitored Item (by ID number)
func (s *MonitoredItemService) DeleteMonitoredItem(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		// id does not exist.
		return
	}

	if item == nil || item.Req == nil || item.Req.ItemToMonitor == nil || item.Req.ItemToMonitor.NodeID == nil {
		return
	}
	nodeid := item.Req.ItemToMonitor.NodeID.String()

	if s == nil || s.nodes == nil || s.nodes[nodeid] == nil {
		return
	}

	// delete the monitored item from all nodes
	// was using slices.DeleteFunc but that is from a newer go version so we'll do it manually with /exp/slices
	// we've got to go backwards because we're deleting from the slice as we go.
	// I'm guessing this loop is less efficient than slices.DeleteFunc but it's what we've got.
	delete(s.items, id)
	for i := len(s.nodes[nodeid]) - 1; i >= 0; i-- {
		n := s.nodes[nodeid][i]
		if n == nil {
			continue
		}
		if n.ID == id {
			s.nodes[nodeid] = slices.Delete(s.nodes[nodeid], i, i+1)
		}
	}
	//slices.DeleteFunc(s.Nodes[nodeid], func(i *MonitoredItem) bool { return i.ID == item.ID })
	if len(s.nodes[nodeid]) == 0 {
		delete(s.nodes, nodeid)
	}

	for i := len(s.subs[item.Sub.ID]) - 1; i >= 0; i-- {
		n := s.subs[item.Sub.ID][i]
		if n == nil {
			continue
		}
		if n.ID == id {
			s.subs[item.Sub.ID] = slices.Delete(s.subs[item.Sub.ID], i, i+1)
		}
	}
	//slices.DeleteFunc(s.Subs[item.Sub.ID], func(i *MonitoredItem) bool { return i.ID == item.ID })
	if len(s.subs[item.Sub.ID]) == 0 {
		delete(s.subs, item.Sub.ID)
	}
}

// function to delete all monitored items associated with a specific sub (as indicated by id number)
func (s *MonitoredItemService) DeleteSub(id types.SubscriptionID) {
	s.mu.Lock()
	items, ok := s.subs[id]
	delete(s.subs, id)
	s.mu.Unlock()

	if !ok {
		return
	}

	for i := range items {
		if items[i] != nil {
			s.DeleteMonitoredItem(items[i].ID)
		}
	}
}

func (s *MonitoredItemService) ChangeNotification(ctx context.Context, n *ua.NodeID) {

	s.mu.Lock()
	defer s.mu.Unlock()
	items, ok := s.nodes[n.String()]

	if !ok {
		// this node isn't monitored - don't have to do anything.
		return
	}

	ns, err := s.backend.Namespace(int(n.Namespace()))

	for i := range items {
		item := items[i]
		if item == nil {
			continue
		}
		val := new(ua.MonitoredItemNotification)
		val.ClientHandle = item.Req.RequestedParameters.ClientHandle
		if err != nil {
			ualog.Warn(ctx, "error getting namespace",
				ualog.Namespace(n.Namespace()), ualog.Err(err),
			)

			val.Value = &ua.DataValue{}
			val.Value.Status = ua.StatusBad
			val.Value.EncodingMask |= ua.DataValueStatusCode
			item.Sub.NotifyChannel <- val
			continue
		}
		dv := ns.Attribute(ctx, n, item.Req.ItemToMonitor.AttributeID)
		val.Value = dv
		item.Sub.NotifyChannel <- val
	}
}

func (s *MonitoredItemService) NextID() uint32 {
	i := s.previousID.Add(uint32(1))
	if i == 0 {
		i = s.previousID.Add(uint32(1))
	}
	return i
}

type MonitoredItem struct {
	ID  uint32
	Sub *Subscription
	Req *ua.MonitoredItemCreateRequest

	//TODO: use this
	Mode ua.MonitoringMode
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.2
func (s *MonitoredItemService) CreateMonitoredItems(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newMonitoredItemServiceLogAttribute("create"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.CreateMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	count := len(req.ItemsToCreate)

	res := make([]*ua.MonitoredItemCreateResult, count)

	subID := types.SubscriptionID(req.SubscriptionID)
	ualog.Debug(ctx, "creating monitored items", ualog.Uint32("sub", uint32(subID)))

	sub, ok := s.backend.Subscription(subID)
	if !ok {
		return nil, errors.New("sub doesn't exist")
	}

	sess := s.backend.Session(ctx, req.RequestHeader)
	if sess == nil || sub.session == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}
	if !sub.session.IsSameAs(sess) {
		return nil, ua.StatusBadSessionIDInvalid
	}

	for i := range req.ItemsToCreate {
		itemreq := req.ItemsToCreate[i]
		nodeid := itemreq.ItemToMonitor.NodeID
		item := MonitoredItem{
			ID:  s.NextID(),
			Sub: sub,
			Req: itemreq,
		}

		// book keeping of the new item
		s.items[item.ID] = &item
		list, ok := s.nodes[item.Req.ItemToMonitor.NodeID.String()]
		if !ok {
			list = make([]*MonitoredItem, 0, 1)
		}
		s.nodes[item.Req.ItemToMonitor.NodeID.String()] = append(list, &item)

		list, ok = s.subs[item.Sub.ID]
		if !ok {
			list = make([]*MonitoredItem, 0, 1)
		}
		s.subs[item.Sub.ID] = append(list, &item)

		ualog.Debug(ctx, "adding monitored item to subscription",
			ualog.Any(ualog.NodeIdKey, nodeid),
			ualog.Uint32("sub", uint32(subID)),
			ualog.Uint32("item_id", item.ID),
			ualog.Uint32("client", itemreq.RequestedParameters.ClientHandle),
		)

		res[i] = &ua.MonitoredItemCreateResult{
			StatusCode:              ua.StatusOK,
			MonitoredItemID:         item.ID,
			RevisedSamplingInterval: sub.RevisedPublishingInterval,
			RevisedQueueSize:        1,
			FilterResult:            ua.NewExtensionObject(nil),
		}
		// do an initial update for the nodeids in the background.
		// These lock the mutex so we can't do them inline here.
		// This will cause them to happen once we unlock.
		go s.ChangeNotification(ctx, nodeid)
	}

	resp := &ua.CreateMonitoredItemsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         res,                    // []StatusCode
		DiagnosticInfos: []*ua.DiagnosticInfo{}, // []*DiagnosticInfo
	}

	return resp, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.3
func (s *MonitoredItemService) ModifyMonitoredItems(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newMonitoredItemServiceLogAttribute("modify"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.ModifyMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.4
func (s *MonitoredItemService) SetMonitoringMode(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newMonitoredItemServiceLogAttribute("set monitoring mode"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.SetMonitoringModeRequest](r)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))

	sess := s.backend.Session(ctx, req.RequestHeader)
	if sess == nil {
		for i := range results {
			results[i] = ua.StatusBadSessionIDInvalid
		}
		return &ua.SetMonitoringModeResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusOK,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			Results:         results,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.items[id]

		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}

		if !item.Sub.session.IsSameAs(sess) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}

		item.Mode = req.MonitoringMode
		results[i] = ua.StatusOK
	}

	return &ua.SetMonitoringModeResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.5
func (s *MonitoredItemService) SetTriggering(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newMonitoredItemServiceLogAttribute("set triggering"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.SetTriggeringRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.6
func (s *MonitoredItemService) DeleteMonitoredItems(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newMonitoredItemServiceLogAttribute("delete"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.DeleteMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess := s.backend.Session(ctx, req.RequestHeader)

	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))
	if sess == nil {
		for i := range results {
			results[i] = ua.StatusBadSessionIDInvalid
		}
		return &ua.DeleteMonitoredItemsResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusOK,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			Results:         results,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}
	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.items[id]
		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}

		if !item.Sub.session.IsSameAs(sess) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}

		// this function gets the lock so we need to do it in the background so it can happen after our lock is released.
		go s.DeleteMonitoredItem(id)
		results[i] = ua.StatusOK
	}

	response := &ua.DeleteMonitoredItemsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
	return response, nil
}
