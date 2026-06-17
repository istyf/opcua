package services

import (
	"context"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateMonitoredItemsChecksSessionOwnership(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	otherSession := newSubscriptionTestSession()
	otherSession.authToken = ua.NewNumericNodeID(1, 404)

	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
	}
	service := NewMonitoredItemService(backend)

	req := &ua.CreateMonitoredItemsRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       1,
			AuthenticationToken: ownerSession.AuthTokenID(),
		},
		SubscriptionID: uint32(sub.ID),
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor: &ua.ReadValueID{
					NodeID:      ua.NewNumericNodeID(1, 1234),
					AttributeID: ua.AttributeIDValue,
				},
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle:     99,
					SamplingInterval: 1000,
					QueueSize:        1,
				},
			},
		},
	}

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	require.IsType(t, &ua.CreateMonitoredItemsResponse{}, resp)

	backend.session = otherSession
	req.RequestHeader.AuthenticationToken = otherSession.AuthTokenID()

	resp, err = service.CreateMonitoredItems(t.Context(), nil, req, 2)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestCreateMonitoredItemsRejectsMissingSession(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000

	backend := &monitoredItemTestBackend{
		session:      nil,
		subscription: sub,
	}
	service := NewMonitoredItemService(backend)

	req := &ua.CreateMonitoredItemsRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       2,
			AuthenticationToken: ownerSession.AuthTokenID(),
		},
		SubscriptionID: uint32(sub.ID),
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor: &ua.ReadValueID{
					NodeID:      ua.NewNumericNodeID(1, 4321),
					AttributeID: ua.AttributeIDValue,
				},
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle:     100,
					SamplingInterval: 1000,
					QueueSize:        1,
				},
			},
		},
	}

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	assert.Nil(t, resp)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, err)
}

func TestCreateMonitoredItemsAcceptsEventNotifierWithEventFilter(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000
	sourceNodeID := ua.NewNumericNodeID(1, 5001)
	namespace := newMonitoredItemTestNamespace(
		monitoredItemTestNode{
			id:            sourceNodeID,
			nodeClass:     ua.NodeClassObject,
			eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
		},
	)

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
		namespace:    namespace,
	}
	service := NewMonitoredItemService(backend)
	filterObject := monitoredItemTestEventFilter("EventId", "Severity")
	filterObject.Value.(*ua.EventFilter).WhereClause = monitoredItemTestSeverityWhereClause(ua.FilterOperatorGreaterThanOrEqual, uint16(100))
	req := monitoredItemTestCreateEventRequest(ownerSession, sub, sourceNodeID, filterObject)
	req.ItemsToCreate[0].RequestedParameters.QueueSize = 7
	req.ItemsToCreate[0].RequestedParameters.DiscardOldest = false

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	createResp, ok := resp.(*ua.CreateMonitoredItemsResponse)
	require.True(t, ok, "expected CreateMonitoredItemsResponse, got %T", resp)
	require.Len(t, createResp.Results, 1)

	result := createResp.Results[0]
	require.Equal(t, ua.StatusOK, result.StatusCode)
	assert.NotZero(t, result.MonitoredItemID)
	assert.Equal(t, float64(1000), result.RevisedSamplingInterval)
	assert.Equal(t, uint32(7), result.RevisedQueueSize)
	filterResult, ok := result.FilterResult.Value.(*ua.EventFilterResult)
	require.True(t, ok, "expected EventFilterResult, got %T", result.FilterResult.Value)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, filterResult.SelectClauseResults)
	require.NotNil(t, filterResult.WhereClauseResult)
	require.Len(t, filterResult.WhereClauseResult.ElementResults, 1)
	assert.Equal(t, ua.StatusOK, filterResult.WhereClauseResult.ElementResults[0].StatusCode)

	item := service.items[result.MonitoredItemID]
	require.NotNil(t, item)
	assert.Equal(t, monitoredItemKindEvent, item.Kind)
	require.NotNil(t, item.EventFilter)
	assert.Len(t, item.EventFilter.SelectClauses, 2)
	assert.Equal(t, uint32(7), item.QueueSize)
	assert.False(t, item.DiscardOldest)

	select {
	case notification := <-sub.NotifyChannel:
		t.Fatalf("event monitored item should not enqueue initial data-change notification: %#v", notification)
	default:
	}
}

func TestCreateMonitoredItemsAcceptsConditionNodeIDSelectClause(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000
	sourceNodeID := ua.NewNumericNodeID(1, 5010)
	namespace := newMonitoredItemTestNamespace(
		monitoredItemTestNode{
			id:            sourceNodeID,
			nodeClass:     ua.NodeClassObject,
			eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
		},
	)

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
		namespace:    namespace,
	}
	service := NewMonitoredItemService(backend)
	filterObject := ua.NewExtensionObject(&ua.EventFilter{
		SelectClauses: []*ua.SimpleAttributeOperand{
			monitoredItemTestConditionNodeIDSelectClause(),
		},
	})
	req := monitoredItemTestCreateEventRequest(ownerSession, sub, sourceNodeID, filterObject)

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	createResp, ok := resp.(*ua.CreateMonitoredItemsResponse)
	require.True(t, ok, "expected CreateMonitoredItemsResponse, got %T", resp)
	require.Len(t, createResp.Results, 1)

	result := createResp.Results[0]
	require.Equal(t, ua.StatusOK, result.StatusCode)
	filterResult, ok := result.FilterResult.Value.(*ua.EventFilterResult)
	require.True(t, ok, "expected EventFilterResult, got %T", result.FilterResult.Value)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK}, filterResult.SelectClauseResults)
	require.NotNil(t, filterResult.WhereClauseResult)
	assert.Empty(t, filterResult.WhereClauseResult.ElementResults)

	decoded := assertCreateMonitoredItemsResponseRoundTrips(t, createResp)
	require.Len(t, decoded.Results, 1)
	decodedFilterResult, ok := decoded.Results[0].FilterResult.Value.(*ua.EventFilterResult)
	require.True(t, ok, "expected decoded EventFilterResult, got %T", decoded.Results[0].FilterResult.Value)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK}, decodedFilterResult.SelectClauseResults)
	require.NotNil(t, decodedFilterResult.WhereClauseResult)
	assert.Empty(t, decodedFilterResult.WhereClauseResult.ElementResults)
}

func TestCreateMonitoredItemsAcceptsUAExpertStyleConditionEventFilter(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000
	sourceNodeID := ua.NewNumericNodeID(1, 5011)
	namespace := newMonitoredItemTestNamespace(
		monitoredItemTestNode{
			id:            sourceNodeID,
			nodeClass:     ua.NodeClassObject,
			eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
		},
	)

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
		namespace:    namespace,
	}
	service := NewMonitoredItemService(backend)
	selectClauses := []*ua.SimpleAttributeOperand{
		monitoredItemTestConditionNodeIDSelectClause(),
		monitoredItemTestSelectClause("EventId"),
		monitoredItemTestSelectClause("EventType"),
		monitoredItemTestSelectClause("SourceName"),
		monitoredItemTestSelectClause("Time"),
		monitoredItemTestSelectClause("Message"),
		monitoredItemTestSelectClause("AckedState", "Id"),
		monitoredItemTestSelectClause("ConfirmedState", "Id"),
		monitoredItemTestSelectClause("ActiveState"),
		monitoredItemTestSelectClause("ActiveState", "Id"),
		monitoredItemTestSelectClause("ActiveState", "EffectiveDisplayName"),
	}
	filterObject := ua.NewExtensionObject(&ua.EventFilter{SelectClauses: selectClauses})
	req := monitoredItemTestCreateEventRequest(ownerSession, sub, sourceNodeID, filterObject)

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	createResp, ok := resp.(*ua.CreateMonitoredItemsResponse)
	require.True(t, ok, "expected CreateMonitoredItemsResponse, got %T", resp)
	require.Len(t, createResp.Results, 1)

	result := createResp.Results[0]
	require.Equal(t, ua.StatusOK, result.StatusCode)
	filterResult, ok := result.FilterResult.Value.(*ua.EventFilterResult)
	require.True(t, ok, "expected EventFilterResult, got %T", result.FilterResult.Value)
	require.Len(t, filterResult.SelectClauseResults, len(selectClauses))
	for _, status := range filterResult.SelectClauseResults {
		assert.Equal(t, ua.StatusOK, status)
	}

	decoded := assertCreateMonitoredItemsResponseRoundTrips(t, createResp)
	require.Len(t, decoded.Results, 1)
	decodedFilterResult, ok := decoded.Results[0].FilterResult.Value.(*ua.EventFilterResult)
	require.True(t, ok, "expected decoded EventFilterResult, got %T", decoded.Results[0].FilterResult.Value)
	require.Len(t, decodedFilterResult.SelectClauseResults, len(selectClauses))
	for _, status := range decodedFilterResult.SelectClauseResults {
		assert.Equal(t, ua.StatusOK, status)
	}
}

func TestCreateMonitoredItemsRejectsInvalidEventNotifierRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		node            types.Node
		filter          *ua.ExtensionObject
		wantStatus      ua.StatusCode
		wantWhereStatus ua.StatusCode
	}{
		{
			name:       "missing node",
			filter:     monitoredItemTestEventFilter("EventId"),
			wantStatus: ua.StatusBadNodeIDUnknown,
		},
		{
			name: "variable node",
			node: monitoredItemTestNode{
				id:            ua.NewNumericNodeID(1, 5002),
				nodeClass:     ua.NodeClassVariable,
				eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
			},
			filter:     monitoredItemTestEventFilter("EventId"),
			wantStatus: ua.StatusBadNodeClassInvalid,
		},
		{
			name: "view node",
			node: monitoredItemTestNode{
				id:            ua.NewNumericNodeID(1, 5005),
				nodeClass:     ua.NodeClassView,
				eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
			},
			filter:     monitoredItemTestEventFilter("EventId"),
			wantStatus: ua.StatusBadNodeClassInvalid,
		},
		{
			name: "object without subscribe bit",
			node: monitoredItemTestNode{
				id:        ua.NewNumericNodeID(1, 5003),
				nodeClass: ua.NodeClassObject,
			},
			filter:     monitoredItemTestEventFilter("EventId"),
			wantStatus: ua.StatusBadNotSupported,
		},
		{
			name: "unsupported filter",
			node: monitoredItemTestNode{
				id:            ua.NewNumericNodeID(1, 5004),
				nodeClass:     ua.NodeClassObject,
				eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
			},
			filter:     ua.NewExtensionObject(&ua.DataChangeFilter{}),
			wantStatus: ua.StatusBadMonitoredItemFilterUnsupported,
		},
		{
			name: "unsupported where clause",
			node: monitoredItemTestNode{
				id:            ua.NewNumericNodeID(1, 5006),
				nodeClass:     ua.NodeClassObject,
				eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
			},
			filter:          monitoredItemTestUnsupportedWhereClauseEventFilter(),
			wantStatus:      ua.StatusBadMonitoredItemFilterUnsupported,
			wantWhereStatus: ua.StatusBadFilterOperatorUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ownerSession := newSubscriptionTestSession()
			sub := NewSubscription()
			sub.ID = 1
			sub.session = ownerSession
			sub.RevisedPublishingInterval = 1000
			namespace := newMonitoredItemTestNamespace()
			sourceNodeID := ua.NewNumericNodeID(1, 5000)
			if tt.node != nil {
				namespace.AddNode(tt.node)
				sourceNodeID = tt.node.ID()
			}
			backend := &monitoredItemTestBackend{
				session:      ownerSession,
				subscription: sub,
				namespace:    namespace,
			}
			service := NewMonitoredItemService(backend)
			req := monitoredItemTestCreateEventRequest(ownerSession, sub, sourceNodeID, tt.filter)

			resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
			require.NoError(t, err)
			createResp, ok := resp.(*ua.CreateMonitoredItemsResponse)
			require.True(t, ok, "expected CreateMonitoredItemsResponse, got %T", resp)
			require.Len(t, createResp.Results, 1)
			assert.Equal(t, tt.wantStatus, createResp.Results[0].StatusCode)
			assert.Zero(t, createResp.Results[0].MonitoredItemID)
			assert.Empty(t, service.items)
			assert.Empty(t, service.nodes)
			assert.Empty(t, service.subs)
			if tt.wantWhereStatus != 0 {
				filterResult, ok := createResp.Results[0].FilterResult.Value.(*ua.EventFilterResult)
				require.True(t, ok, "expected EventFilterResult, got %T", createResp.Results[0].FilterResult.Value)
				require.NotNil(t, filterResult.WhereClauseResult)
				require.Len(t, filterResult.WhereClauseResult.ElementResults, 1)
				assert.Equal(t, tt.wantWhereStatus, filterResult.WhereClauseResult.ElementResults[0].StatusCode)
			}
		})
	}
}

func TestEmitEventQueuesMatchingEventFieldList(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000
	sourceNodeID := ua.NewNumericNodeID(1, 6001)
	namespace := newMonitoredItemTestNamespace(
		monitoredItemTestNode{
			id:            sourceNodeID,
			nodeClass:     ua.NodeClassObject,
			eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
		},
	)

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
		namespace:    namespace,
	}
	service := NewMonitoredItemService(backend)
	filterObject := monitoredItemTestEventFilter("Severity", "Message", "SourceNode")
	filterObject.Value.(*ua.EventFilter).WhereClause = monitoredItemTestSeverityWhereClause(ua.FilterOperatorGreaterThanOrEqual, uint16(100))
	req := monitoredItemTestCreateEventRequest(ownerSession, sub, sourceNodeID, filterObject)

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	createResp, ok := resp.(*ua.CreateMonitoredItemsResponse)
	require.True(t, ok, "expected CreateMonitoredItemsResponse, got %T", resp)
	require.Len(t, createResp.Results, 1)
	require.Equal(t, ua.StatusOK, createResp.Results[0].StatusCode)

	event := &types.Event{
		SourceNode: sourceNodeID,
		Message:    ua.NewLocalizedText("threshold crossed"),
		Severity:   250,
	}
	require.NoError(t, service.EmitEvent(t.Context(), sourceNodeID, event))

	select {
	case notification := <-sub.NotifyChannel:
		require.Equal(t, subscriptionNotificationKindEvent, notification.kind)
		fieldList := notification.event
		require.NotNil(t, fieldList)
		assert.Equal(t, uint32(55), fieldList.ClientHandle)
		require.Len(t, fieldList.EventFields, 3)
		assert.Equal(t, uint64(250), fieldList.EventFields[0].Uint())
		assert.Equal(t, "threshold crossed", fieldList.EventFields[1].String())
		assert.Same(t, sourceNodeID, fieldList.EventFields[2].Value())
	default:
		t.Fatal("expected a queued event field list")
	}
}

func TestEmitEventSkipsNonMatchingEventFilter(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000
	sourceNodeID := ua.NewNumericNodeID(1, 6002)
	namespace := newMonitoredItemTestNamespace(
		monitoredItemTestNode{
			id:            sourceNodeID,
			nodeClass:     ua.NodeClassObject,
			eventNotifier: ua.EventNotifierTypeSubscribeToEvents,
		},
	)

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
		namespace:    namespace,
	}
	service := NewMonitoredItemService(backend)
	filterObject := monitoredItemTestEventFilter("Severity")
	filterObject.Value.(*ua.EventFilter).WhereClause = monitoredItemTestSeverityWhereClause(ua.FilterOperatorGreaterThanOrEqual, uint16(500))
	req := monitoredItemTestCreateEventRequest(ownerSession, sub, sourceNodeID, filterObject)

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	createResp, ok := resp.(*ua.CreateMonitoredItemsResponse)
	require.True(t, ok, "expected CreateMonitoredItemsResponse, got %T", resp)
	require.Len(t, createResp.Results, 1)
	require.Equal(t, ua.StatusOK, createResp.Results[0].StatusCode)

	require.NoError(t, service.EmitEvent(t.Context(), sourceNodeID, &types.Event{Severity: 499}))

	select {
	case notification := <-sub.NotifyChannel:
		t.Fatalf("did not expect event notification for non-matching filter: %#v", notification)
	default:
	}
}

type monitoredItemTestBackend struct {
	session      types.Session
	subscription *Subscription
	namespace    types.NameSpace
}

func (b *monitoredItemTestBackend) RegisterHandler(int, Handler) {}

func (b *monitoredItemTestBackend) Namespace(int) (types.NameSpace, error) {
	if b.namespace != nil {
		return b.namespace, nil
	}
	return nil, context.Canceled
}

func (b *monitoredItemTestBackend) Session(context.Context, *ua.RequestHeader) types.Session {
	return b.session
}

func (b *monitoredItemTestBackend) Subscription(id types.SubscriptionID) (*Subscription, bool) {
	if b.subscription == nil || b.subscription.ID != id {
		return nil, false
	}
	return b.subscription, true
}

func assertCreateMonitoredItemsResponseRoundTrips(t *testing.T, resp *ua.CreateMonitoredItemsResponse) *ua.CreateMonitoredItemsResponse {
	t.Helper()

	encoded, err := ua.Encode(resp)
	require.NoError(t, err)

	var decoded ua.CreateMonitoredItemsResponse
	n, err := ua.Decode(encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, len(encoded), n)

	return &decoded
}

func monitoredItemTestCreateEventRequest(session types.Session, sub *Subscription, sourceNodeID *ua.NodeID, filter *ua.ExtensionObject) *ua.CreateMonitoredItemsRequest {
	return &ua.CreateMonitoredItemsRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       3,
			AuthenticationToken: session.AuthTokenID(),
		},
		SubscriptionID: uint32(sub.ID),
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor: &ua.ReadValueID{
					NodeID:      sourceNodeID,
					AttributeID: ua.AttributeIDEventNotifier,
				},
				MonitoringMode: ua.MonitoringModeReporting,
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle:     55,
					SamplingInterval: 1000,
					Filter:           filter,
					QueueSize:        1,
					DiscardOldest:    true,
				},
			},
		},
	}
}

func monitoredItemTestEventFilter(fieldNames ...string) *ua.ExtensionObject {
	selectClauses := make([]*ua.SimpleAttributeOperand, len(fieldNames))
	for i, name := range fieldNames {
		selectClauses[i] = &ua.SimpleAttributeOperand{
			TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
			BrowsePath: []*ua.QualifiedName{
				{NamespaceIndex: 0, Name: name},
			},
			AttributeID: ua.AttributeIDValue,
		}
	}
	return ua.NewExtensionObject(&ua.EventFilter{
		SelectClauses: selectClauses,
	})
}

func monitoredItemTestUnsupportedWhereClauseEventFilter() *ua.ExtensionObject {
	filter := monitoredItemTestEventFilter("Severity")
	filter.Value.(*ua.EventFilter).WhereClause = &ua.ContentFilter{
		Elements: []*ua.ContentFilterElement{
			{
				FilterOperator: ua.FilterOperatorLike,
				FilterOperands: []*ua.ExtensionObject{
					ua.NewExtensionObject(monitoredItemTestSelectClause("Severity")),
					ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(500))}),
				},
			},
		},
	}
	return filter
}

type monitoredItemTestNamespace struct {
	nodes map[string]types.Node
}

func newMonitoredItemTestNamespace(nodes ...types.Node) *monitoredItemTestNamespace {
	ns := &monitoredItemTestNamespace{nodes: make(map[string]types.Node, len(nodes))}
	for _, node := range nodes {
		ns.AddNode(node)
	}
	return ns
}

func (ns *monitoredItemTestNamespace) Name() string { return "urn:test:monitored-items" }

func (ns *monitoredItemTestNamespace) AddNode(node types.Node) types.Node {
	ns.nodes[node.ID().String()] = node
	return node
}

func (ns *monitoredItemTestNamespace) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}
	return ns.nodes[id.String()]
}

func (ns *monitoredItemTestNamespace) Browse(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
	return &ua.BrowseResult{StatusCode: ua.StatusOK}
}

func (ns *monitoredItemTestNamespace) ID() uint16 { return 1 }

func (ns *monitoredItemTestNamespace) SetID(uint16) {}

func (ns *monitoredItemTestNamespace) Attribute(ctx context.Context, id *ua.NodeID, attr ua.AttributeID) *ua.DataValue {
	node := ns.Node(id)
	if node == nil {
		return &ua.DataValue{Status: ua.StatusBadNodeIDUnknown}
	}
	attrValue, err := node.Attribute(ctx, attr)
	if err != nil || attrValue == nil {
		return &ua.DataValue{Status: ua.StatusBadAttributeIDInvalid}
	}
	return attrValue.Value
}

func (ns *monitoredItemTestNamespace) SetAttribute(context.Context, *ua.NodeID, ua.AttributeID, *ua.DataValue) ua.StatusCode {
	return ua.StatusBadNotWritable
}

func (ns *monitoredItemTestNamespace) NewQualifiedName(name string) *ua.QualifiedName {
	return &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: name}
}

func (ns *monitoredItemTestNamespace) NextAvailableID() *ua.NodeID {
	return ua.NewNumericNodeID(ns.ID(), 1)
}

type monitoredItemTestNode struct {
	id            *ua.NodeID
	nodeClass     ua.NodeClass
	eventNotifier ua.EventNotifierType
}

func (n monitoredItemTestNode) ID() *ua.NodeID { return n.id }

func (n monitoredItemTestNode) BrowseName() *ua.QualifiedName {
	return &ua.QualifiedName{NamespaceIndex: n.id.Namespace(), Name: "TestNode"}
}

func (n monitoredItemTestNode) DisplayName(context.Context) *ua.LocalizedText {
	return ua.NewLocalizedText("TestNode")
}

func (n monitoredItemTestNode) NodeClass() ua.NodeClass { return n.nodeClass }

func (n monitoredItemTestNode) AddComponent(types.Node) types.Node { return n }

func (n monitoredItemTestNode) AddComponents(...types.Node) types.Node { return n }

func (n monitoredItemTestNode) AddRef(types.ReferenceWrapper) {}

func (n monitoredItemTestNode) References() types.ReferenceCollection { return nil }

func (n monitoredItemTestNode) Attribute(context.Context, ua.AttributeID) (*types.AttrValue, error) {
	return &types.AttrValue{
		Value: &ua.DataValue{
			Value: ua.MustVariant(uint8(n.eventNotifier)),
		},
	}, nil
}

func (n monitoredItemTestNode) SetAttribute(context.Context, ua.AttributeID, *ua.DataValue) error {
	return nil
}
