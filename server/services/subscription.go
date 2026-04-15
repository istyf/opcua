package services

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type SubscriptionServiceBackend interface {
	HandlerRegistrator
	NamespaceProvider
	SessionProvider
	SubscriptionDeleter
	Config() types.ServerConfig
}

// SubscriptionService implements the Subscription Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.14
type SubscriptionService struct {
	srv SubscriptionServiceBackend

	// pub sub stuff
	mu                         sync.Mutex
	subs                       map[types.SubscriptionID]*Subscription
	previousID                 atomic.Uint32
	minPublishingInterval      float64
	minKeepAliveCount          uint32
	minLifetimeCount           uint32
	maxSubscriptions           uint32
	maxSubscriptionsPerSession uint32
	maxSubscriptionOperations  uint32
}

func NewSubscriptionService(b SubscriptionServiceBackend) *SubscriptionService {
	ss := &SubscriptionService{
		srv:                        b,
		subs:                       make(map[types.SubscriptionID]*Subscription),
		minPublishingInterval:      float64(b.Config().MinSubscriptionPublishingInterval() / time.Millisecond),
		minKeepAliveCount:          b.Config().MinSubscriptionMaxKeepAliveCount(),
		minLifetimeCount:           b.Config().MinSubscriptionLifetimeCount(),
		maxSubscriptions:           b.Config().MaxSubscriptions(),
		maxSubscriptionsPerSession: b.Config().MaxSubscriptionsPerSession(),
		maxSubscriptionOperations:  b.Config().MaxSubscriptionOperationsPerCall(),
	}

	b.RegisterHandler(id.CreateSubscriptionRequest_Encoding_DefaultBinary, ss.CreateSubscription)
	b.RegisterHandler(id.ModifySubscriptionRequest_Encoding_DefaultBinary, ss.ModifySubscription)
	b.RegisterHandler(id.SetPublishingModeRequest_Encoding_DefaultBinary, ss.SetPublishingMode)
	b.RegisterHandler(id.PublishRequest_Encoding_DefaultBinary, ss.Publish)
	b.RegisterHandler(id.RepublishRequest_Encoding_DefaultBinary, ss.Republish)
	b.RegisterHandler(id.TransferSubscriptionsRequest_Encoding_DefaultBinary, ss.TransferSubscriptions)
	b.RegisterHandler(id.DeleteSubscriptionsRequest_Encoding_DefaultBinary, ss.DeleteSubscriptions)

	return ss
}

var newSubscriptionServiceLogAttribute = newServiceLogAttributeCreatorForSet("subscription")

const (
	// DefaultMinSubscriptionPublishingInterval is the default smallest supported
	// publishing interval used when the server config does not override it.
	DefaultMinSubscriptionPublishingInterval = time.Second
	defaultMinSupportedPublishingIntervalMS  = float64(DefaultMinSubscriptionPublishingInterval / time.Millisecond)
	// DefaultMinSubscriptionMaxKeepAliveCount is the default smallest supported
	// keepalive count used when the server config does not override it.
	DefaultMinSubscriptionMaxKeepAliveCount = 10
	// DefaultMinSubscriptionLifetimeCount is the default smallest supported
	// lifetime count used when the server config does not override it.
	DefaultMinSubscriptionLifetimeCount = 30
)

func revisePublishingInterval(requested, minSupported float64) float64 {
	if minSupported <= 0 {
		minSupported = defaultMinSupportedPublishingIntervalMS
	}
	if requested <= 0 {
		return minSupported
	}
	return max(requested, minSupported)
}

func reviseMaxKeepAliveCount(requested, minSupported uint32) uint32 {
	if minSupported == 0 {
		minSupported = DefaultMinSubscriptionMaxKeepAliveCount
	}
	if requested == 0 {
		return minSupported
	}
	return max(requested, minSupported)
}

func reviseLifetimeCount(requested, minSupported, revisedKeepAliveCount uint32) uint32 {
	if minSupported == 0 {
		minSupported = DefaultMinSubscriptionLifetimeCount
	}

	specMin := revisedKeepAliveCount * 3
	minLifetime := max(minSupported, specMin)
	if requested == 0 {
		return minLifetime
	}
	return max(requested, minLifetime)
}

func newModifySubscriptionResponse(requestHandle uint32, revisedPublishingInterval float64, revisedLifetimeCount, revisedMaxKeepAliveCount uint32) *ua.ModifySubscriptionResponse {
	return &ua.ModifySubscriptionResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      requestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		RevisedPublishingInterval: revisedPublishingInterval,
		RevisedLifetimeCount:      revisedLifetimeCount,
		RevisedMaxKeepAliveCount:  revisedMaxKeepAliveCount,
	}
}

func newSetPublishingModeResponse(requestHandle uint32, results []ua.StatusCode) *ua.SetPublishingModeResponse {
	return &ua.SetPublishingModeResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      requestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
}

func (s *SubscriptionService) NextID() types.SubscriptionID {
	id := types.SubscriptionID(s.previousID.Add(1))
	if id == 0 {
		id = types.SubscriptionID(s.previousID.Add(1))
	}
	return id
}

func sameSession(left, right types.Session) bool {
	if left == nil || right == nil {
		return false
	}
	return left.AuthTokenID().String() == right.AuthTokenID().String()
}

func (s *SubscriptionService) exceedsSubscriptionLimits(session types.Session) bool {
	if s.maxSubscriptions > 0 && len(s.subs) >= int(s.maxSubscriptions) {
		return true
	}
	if s.maxSubscriptionsPerSession == 0 {
		return false
	}

	count := 0
	for _, sub := range s.subs {
		if sub != nil && sameSession(sub.session, session) {
			count++
			if count >= int(s.maxSubscriptionsPerSession) {
				return true
			}
		}
	}
	return false
}

func (s *SubscriptionService) Get(id types.SubscriptionID) (*Subscription, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subs[id]
	return sub, ok
}

// get rid of all references to a subscription and all monitored items that are pointed at this subscription.
func (s *SubscriptionService) DeleteSubscription(ctx context.Context, id types.SubscriptionID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subs[id]
	if ok {
		sub.Mu.Lock()
		if sub.running {
			sub.running = false
			close(sub.shutdown)
		}
		sub.Mu.Unlock()
	}

	delete(s.subs, id)

	// ask the monitored item service to purge out any items that use this subscription
	s.srv.DeleteSubscription(id)
}

func (s *SubscriptionService) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	subs := make([]*Subscription, 0, len(s.subs))
	for _, sub := range s.subs {
		if sub != nil {
			subs = append(subs, sub)
		}
	}
	s.mu.Unlock()

	var err error
	for _, sub := range subs {
		if stopErr := sub.Stop(ctx); stopErr != nil && err == nil {
			err = stopErr
		}
	}

	return err
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.14.2
func (s *SubscriptionService) CreateSubscription(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSubscriptionServiceLogAttribute("create"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.CreateSubscriptionRequest](r)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		panic("subscription service requires a non-nil secure channel")
	}

	session := s.srv.Session(ctx, r.Header())
	if session == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.exceedsSubscriptionLimits(session) {
		return nil, ua.StatusBadTooManySubscriptions
	}

	newsubid := s.NextID()
	ualog.Info(ctx, "new subscription created",
		ualog.Uint32("sub", uint32(newsubid)),
		ualog.Any("remote", sc.RemoteAddr()),
	)

	sub := NewSubscription()
	sub.srv = s
	sub.session = session
	sub.Channel = sc
	sub.ID = newsubid
	sub.RevisedPublishingInterval = revisePublishingInterval(req.RequestedPublishingInterval, s.minPublishingInterval)
	sub.RevisedMaxKeepAliveCount = reviseMaxKeepAliveCount(req.RequestedMaxKeepAliveCount, s.minKeepAliveCount)
	sub.RevisedLifetimeCount = reviseLifetimeCount(req.RequestedLifetimeCount, s.minLifetimeCount, sub.RevisedMaxKeepAliveCount)
	sub.MaxNotificationsPerPublish = req.MaxNotificationsPerPublish
	sub.PublishingEnabled = req.PublishingEnabled
	sub.Priority = req.Priority

	s.subs[newsubid] = sub
	sub.running = true
	sub.Start(ctx)

	resp := &ua.CreateSubscriptionResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID:            uint32(newsubid),
		RevisedPublishingInterval: sub.RevisedPublishingInterval,
		RevisedLifetimeCount:      sub.RevisedLifetimeCount,
		RevisedMaxKeepAliveCount:  sub.RevisedMaxKeepAliveCount,
	}
	return resp, nil
}

// ModifySubscription revises the requested values using the same rules as
// CreateSubscription, applies the negotiated values to the live subscription,
// and returns the revised values to the client.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.14.3
func (s *SubscriptionService) ModifySubscription(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSubscriptionServiceLogAttribute("modify"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.ModifySubscriptionRequest](r)
	if err != nil {
		return nil, err
	}
	session := s.srv.Session(ctx, req.RequestHeader)
	if session == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	subscriptionID := types.SubscriptionID(req.SubscriptionID)
	sub, ok := s.subs[subscriptionID]
	if !ok {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	if !sameSession(sub.session, session) {
		return nil, ua.StatusBadSessionIDInvalid
	}

	revisedPublishingInterval := revisePublishingInterval(req.RequestedPublishingInterval, s.minPublishingInterval)
	revisedMaxKeepAliveCount := reviseMaxKeepAliveCount(req.RequestedMaxKeepAliveCount, s.minKeepAliveCount)
	revisedLifetimeCount := reviseLifetimeCount(req.RequestedLifetimeCount, s.minLifetimeCount, revisedMaxKeepAliveCount)

	revisedReq := &ua.ModifySubscriptionRequest{
		RequestedPublishingInterval: revisedPublishingInterval,
		RequestedLifetimeCount:      revisedLifetimeCount,
		RequestedMaxKeepAliveCount:  revisedMaxKeepAliveCount,
		MaxNotificationsPerPublish:  req.MaxNotificationsPerPublish,
		Priority:                    req.Priority,
	}
	done := make(chan struct{})
	sub.ModifyChannel <- subscriptionModify{req: revisedReq, done: done}
	<-done

	return newModifySubscriptionResponse(
		req.RequestHeader.RequestHandle,
		revisedPublishingInterval,
		revisedLifetimeCount,
		revisedMaxKeepAliveCount,
	), nil
}

// SetPublishingMode enables or disables publishing for the requested
// subscriptions, while preserving queued notifications and leaving keep-alive
// processing active for disabled subscriptions.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.14.4
func (s *SubscriptionService) SetPublishingMode(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSubscriptionServiceLogAttribute("set publishing mode"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.SetPublishingModeRequest](r)
	if err != nil {
		return nil, err
	}
	if len(req.SubscriptionIDs) == 0 {
		return nil, ua.StatusBadNothingToDo
	}
	if s.maxSubscriptionOperations > 0 && uint32(len(req.SubscriptionIDs)) > s.maxSubscriptionOperations {
		return nil, ua.StatusBadTooManyOperations
	}

	session := s.srv.Session(ctx, req.RequestHeader)

	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	if session == nil {
		for i := range results {
			results[i] = ua.StatusBadSessionIDInvalid
		}
		return newSetPublishingModeResponse(req.RequestHeader.RequestHandle, results), nil
	}

	for i, id := range req.SubscriptionIDs {
		sub, ok := s.subs[types.SubscriptionID(id)]
		if !ok {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		if !sameSession(sub.session, session) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}

		done := make(chan struct{})
		sub.SetPublishingModeChannel <- subscriptionPublishingMode{enabled: req.PublishingEnabled, done: done}
		<-done
		results[i] = ua.StatusOK
	}

	return newSetPublishingModeResponse(req.RequestHeader.RequestHandle, results), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.5
func (s *SubscriptionService) Publish(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSubscriptionServiceLogAttribute("publish"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.PublishRequest](r)
	if err != nil {
		ualog.Error(ctx, "bad PublishRequest struct", ualog.Err(err))
		return nil, err
	}

	session := s.srv.Session(ctx, req.RequestHeader)

	if session == nil {
		response := &ua.PublishResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusBadSessionIDInvalid,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			SubscriptionID:           0,
			MoreNotifications:        false,
			NotificationMessage:      &ua.NotificationMessage{NotificationData: []*ua.ExtensionObject{}},
			AvailableSequenceNumbers: []uint32{}, // an empty array indicates that we don't support retransmission of messages
			Results:                  []ua.StatusCode{},
			DiagnosticInfos:          []*ua.DiagnosticInfo{},
		}

		return response, nil
	}

	select {
	case session.PublishRequestChannel() <- types.PubReq{Req: req, ID: reqID}:
	default:
		ualog.Warn(ctx, "too many publish requests")
	}

	// per opcua spec, we don't respond now.  When data is available on the subscription,
	// the Subscription will respond in the background.
	return nil, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.6
func (s *SubscriptionService) Republish(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSubscriptionServiceLogAttribute("republish"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.RepublishRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.7
func (s *SubscriptionService) TransferSubscriptions(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSubscriptionServiceLogAttribute("transfer"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.TransferSubscriptionsRequest](r)
	if err != nil {
		return nil, err
	}

	// When this gets implemented, be sure to check the subscription session vs the request session!
	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.8
func (s *SubscriptionService) DeleteSubscriptions(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newSubscriptionServiceLogAttribute("delete"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.DeleteSubscriptionsRequest](r)
	if err != nil {
		return nil, err
	}
	session := s.srv.Session(ctx, req.Header())

	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	if session == nil {
		for i := range results {
			results[i] = ua.StatusBadSessionIDInvalid
		}
		return &ua.DeleteSubscriptionsResponse{
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
	for i := range req.SubscriptionIDs {

		subid := types.SubscriptionID(req.SubscriptionIDs[i])
		ualog.Info(ctx, "subscription deleted by client", ualog.Uint32("sub", uint32(subid)))
		sub, ok := s.subs[subid]
		if !ok {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		if !session.IsSameAs(sub.session) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}
		// delete subscription gets the lock so we set them up to run in the background
		// once this function releases its lock
		go s.DeleteSubscription(ctx, subid)
		results[i] = ua.StatusOK
	}
	return &ua.DeleteSubscriptionsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,                //   []StatusCode
		DiagnosticInfos: []*ua.DiagnosticInfo{}, //   []*DiagnosticInfo
	}, nil
}

// This is the type that with its run() function will work in the bakground fullfilling subscription
// publishes.
//
// MonitoredItems will send updates on the NotifyChannel to let the background task know that
// an event has occured that needs to be published.
type Subscription struct {
	srv                        *SubscriptionService
	session                    types.Session
	ID                         types.SubscriptionID
	RevisedPublishingInterval  float64
	RevisedLifetimeCount       uint32
	RevisedMaxKeepAliveCount   uint32
	MaxNotificationsPerPublish uint32
	PublishingEnabled          bool
	Priority                   uint8
	Channel                    *uasc.SecureChannel
	SequenceID                 uint32
	//SeqNums                   map[uint32]struct{}
	T *time.Ticker

	NotifyChannel            chan *ua.MonitoredItemNotification
	ModifyChannel            chan subscriptionModify
	SetPublishingModeChannel chan subscriptionPublishingMode

	// Runtime state owned by the subscription goroutine.
	publishQueue     map[uint32]*ua.MonitoredItemNotification
	keepaliveCounter int
	lifetimeCounter  int

	// the running flag and shutdown channel are used to signal the background task that it should stop.
	// multiple places can kill the subscription so make sure you check the running flag using the mutex
	// before closing the shutdown channel.
	Mu       sync.Mutex
	running  bool
	shutdown chan struct{}
	done     chan struct{}
}

type subscriptionModify struct {
	req  *ua.ModifySubscriptionRequest
	done chan struct{}
}

type subscriptionPublishingMode struct {
	enabled bool
	done    chan struct{}
}

func NewSubscription() *Subscription {
	return &Subscription{
		//SeqNums:       map[uint32]struct{}{},
		NotifyChannel:            make(chan *ua.MonitoredItemNotification, 100),
		ModifyChannel:            make(chan subscriptionModify, 2),
		SetPublishingModeChannel: make(chan subscriptionPublishingMode, 2),
		publishQueue:             make(map[uint32]*ua.MonitoredItemNotification),
		shutdown:                 make(chan struct{}),
		done:                     make(chan struct{}),
	}
}

func (s *Subscription) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}

	s.Mu.Lock()
	if s.running {
		s.running = false
		close(s.shutdown)
	}
	done := s.done
	s.Mu.Unlock()

	if done == nil {
		return nil
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Subscription) Update(req *ua.ModifySubscriptionRequest) {
	s.RevisedPublishingInterval = req.RequestedPublishingInterval
	s.RevisedLifetimeCount = req.RequestedLifetimeCount
	s.RevisedMaxKeepAliveCount = req.RequestedMaxKeepAliveCount
	s.MaxNotificationsPerPublish = req.MaxNotificationsPerPublish
	s.Priority = req.Priority
}

func (s *Subscription) resetTicker() {
	if s.T != nil {
		s.T.Stop()
	}
	s.T = time.NewTicker(time.Millisecond * time.Duration(s.RevisedPublishingInterval))
}

func (s *Subscription) applyModifyRequest(req *ua.ModifySubscriptionRequest) {
	intervalChanged := s.RevisedPublishingInterval != req.RequestedPublishingInterval
	s.Update(req)
	if intervalChanged {
		// The revised publishing interval must affect the running subscription,
		// not just the stored state returned by ModifySubscription.
		s.resetTicker()
	}
}

func (s *Subscription) applySetPublishingMode(enabled bool) {
	s.PublishingEnabled = enabled
}

func (s *Subscription) Start(ctx context.Context) {
	ctx = ualog.WithAttrs(ctx, ualog.Uint32("sub", uint32(s.ID)))
	go s.run(ctx)
}

func (s *Subscription) keepalive(pubreq types.PubReq) error {
	eo := make([]*ua.ExtensionObject, 0)

	msg := ua.NotificationMessage{
		SequenceNumber:   s.nextKeepaliveSequenceNumber(),
		PublishTime:      time.Now(),
		NotificationData: eo,
	}

	response := &ua.PublishResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      pubreq.Req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID:           uint32(s.ID),
		MoreNotifications:        false,
		NotificationMessage:      &msg,
		AvailableSequenceNumbers: []uint32{}, // an empty array indicates taht we don't support retransmission of messages
		Results:                  []ua.StatusCode{},
		DiagnosticInfos:          []*ua.DiagnosticInfo{},
	}
	err := s.Channel.SendResponseWithContext(context.Background(), pubreq.ID, response)
	if err != nil {
		return err
	}
	return nil
}

func (s *Subscription) canPublishNotifications(pendingNotificationCount int) bool {
	return s.PublishingEnabled && pendingNotificationCount > 0
}

func (s *Subscription) shouldSendKeepalive(keepaliveCount int) bool {
	return keepaliveCount >= int(s.RevisedMaxKeepAliveCount)
}

func (s *Subscription) shouldTimeout(lifetimeCount int) bool {
	return lifetimeCount >= int(s.RevisedLifetimeCount)
}

func (s *Subscription) nextKeepaliveSequenceNumber() uint32 {
	if s.SequenceID == 0 {
		return 1
	}
	return s.SequenceID + 1
}

func (s *Subscription) nextPublishBatch(publishQueue map[uint32]*ua.MonitoredItemNotification) ([]*ua.MonitoredItemNotification, bool) {
	maxCount := len(publishQueue)
	if s.MaxNotificationsPerPublish > 0 && int(s.MaxNotificationsPerPublish) < maxCount {
		maxCount = int(s.MaxNotificationsPerPublish)
	}

	finalItems := make([]*ua.MonitoredItemNotification, 0, maxCount)
	for clientHandle, notification := range publishQueue {
		finalItems = append(finalItems, notification)
		delete(publishQueue, clientHandle)
		if len(finalItems) == maxCount {
			break
		}
	}

	return finalItems, len(publishQueue) > 0
}

// this function should be run as a go-routine and will handle sending data out
// to the client at the correct rate assuming there are publish requests queued up.
// if the function returns it deletes the subscription
func (s *Subscription) run(ctx context.Context) {
	// if this go routine dies, we need to delete ourselves.
	defer func() {
		close(s.done)
		ualog.Info(ctx, "subscription shutting down")
		s.srv.DeleteSubscription(ctx, s.ID)
	}()

	s.resetTicker()
	defer s.T.Stop()

	// This is the master run event loop.  It has effectively 3 states that it can be in.  The first two are designated with
	// the labels L0, and L2.  Everything after the L2 loop is the third state where we send any pending notifications.
	// The states always go L0 -> L2 -> Sending -> L0.  L0 and L2 are both places where we wait so they are done as for loops with
	// breaks to go to the next state.
	// The sending state always runs to completion.
	//
	// L0 waits for our notification interval to expire.  Any notifications that come in
	// while waiting will be stored in the publishQueue.  Once the interval expires, we'll move on to L2 if we've got notifications.
	// In L2 we wait for a publish request.  If we get one, we'll publish the notifications in the publishQueue.  If we don't
	// get a publish request, we'll continue to count intervals without a publish request.
	//
	// In L0 and L2, If we get to the lifetime count without a publish request, we'll kill the subscription.
	for {
		// Collect notifications until our publication interval is ready
	L0:
		for {
			select {
			case <-s.shutdown:
				return
			case newNotification := <-s.NotifyChannel:
				s.publishQueue[newNotification.ClientHandle] = newNotification
			case <-s.T.C:
				if !s.canPublishNotifications(len(s.publishQueue)) {
					// nothing to publish, increment the keepalive counter and send a keepalive if it
					// has been enough intervals.
					s.keepaliveCounter++
					if s.shouldSendKeepalive(s.keepaliveCounter) {
						s.keepaliveCounter = 0
						select {
						case pubreq := <-s.session.PublishRequestChannel():
							err := s.keepalive(pubreq)
							if err != nil {
								ualog.Warn(ctx, "problem sending keepalive to subscription", ualog.Err(err))
								return
							}
						default:
							s.lifetimeCounter++
							if s.shouldTimeout(s.lifetimeCounter) {
								ualog.Warn(ctx, "subscription timed out")
								return
							}
						}
					}
					continue // nothing to publish this interval
				}
				// we have things to publish so we'll break out to do that.
				break L0
			case update := <-s.ModifyChannel:
				s.applyModifyRequest(update.req)
				close(update.done)
			case update := <-s.SetPublishingModeChannel:
				s.applySetPublishingMode(update.enabled)
				close(update.done)
			}
		}
		var pubreq types.PubReq

		// now we need to continue to collect notifications until we've got a publish request
	L2:
		for {
			select {
			case <-s.shutdown:
				return
			case pubreq = <-s.session.PublishRequestChannel():
				// once we get a publish request, we should move on to publish them back
				break L2
			case newNotification := <-s.NotifyChannel:
				s.publishQueue[newNotification.ClientHandle] = newNotification

			case <-s.T.C:
				// we had another tick without a publish request.
				s.lifetimeCounter++
				if s.shouldTimeout(s.lifetimeCounter) {
					ualog.Warn(ctx, "subscription timed out")
					return
				}
			case update := <-s.ModifyChannel:
				s.applyModifyRequest(update.req)
				close(update.done)
			case update := <-s.SetPublishingModeChannel:
				s.applySetPublishingMode(update.enabled)
				close(update.done)
			}
		}
		s.lifetimeCounter = 0
		s.keepaliveCounter = 0

		s.SequenceID++
		if s.SequenceID == 0 {
			// per the spec, the sequence ID cannot be 0
			s.SequenceID = 1
		}

		ualog.Debug(ctx, "got publish request", ualog.Uint32("sequence", s.SequenceID))

		// then get all the tags and send them back to the client

		//for x := range pubreq.Req.SubscriptionAcknowledgements {
		//a := pubreq.Req.SubscriptionAcknowledgements[x]
		//delete(s.SeqNums, a.SequenceNumber)
		//}

		finalItems, moreNotifications := s.nextPublishBatch(s.publishQueue)

		dcn := ua.DataChangeNotification{
			MonitoredItems:  finalItems,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}
		eo := make([]*ua.ExtensionObject, 1)
		eo[0] = ua.NewExtensionObject(&dcn)
		eo[0].UpdateMask()

		msg := ua.NotificationMessage{
			SequenceNumber:   s.SequenceID,
			PublishTime:      time.Now(),
			NotificationData: eo,
		}
		//s.SeqNums[s.SequenceID] = struct{}{}

		response := &ua.PublishResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      pubreq.Req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusOK,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			SubscriptionID:           uint32(s.ID),
			MoreNotifications:        moreNotifications,
			NotificationMessage:      &msg,
			AvailableSequenceNumbers: []uint32{}, // an empty array indicates taht we don't support retransmission of messages
			Results:                  []ua.StatusCode{},
			DiagnosticInfos:          []*ua.DiagnosticInfo{},
		}
		err := s.Channel.SendResponseWithContext(context.Background(), pubreq.ID, response)
		if err != nil {
			ualog.Error(ctx, "problem sending channel response", ualog.Err(err))
			ualog.Error(ctx, "killing subscription")
			return
		}

		ualog.Debug(ctx, "published items", ualog.Int("count", len(s.publishQueue)))

		// wait till we've got a publish request.
	}
}

//PublishRequest_Encoding_DefaultBinary
