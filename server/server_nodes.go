package server

import (
	"fmt"
	"math"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

func mustHaveServerNode[T any](nodeID *ua.NodeID, ns types.NameSpace) T {
	theNode := ns.Node(nodeID)
	if theNode == nil {
		panic("expected server node " + nodeID.String() + " but got nil!")
	}

	if typedNode, ok := theNode.(T); ok {
		return typedNode
	}

	var zero T
	panic(fmt.Sprintf("failed to type cast server node %s to %T", nodeID.String(), zero))
}

func WireupNamespacesArrayNodeValue(s types.Server, ns types.NameSpace) {
	nodeID := ua.NewNumericNodeID(0, id.Server_NamespaceArray)
	theNode := mustHaveServerNode[types.VariableNode](nodeID, ns)

	theNode.SetValueFunc(func() *ua.DataValue {
		n := s.Namespaces()
		ns := make([]string, len(n))
		for i := range ns {
			ns[i] = n[i].Name()
		}
		return values.DataValueFromValue(ns)
	})
}

func WireupServerCapabilityNodeValue(s types.Server, ns types.NameSpace) {
	advertiseUint32Limit := func(limit uint32) uint32 {
		if limit == 0 {
			return math.MaxUint32
		}
		return limit
	}
	advertiseUint16Limit := func(limit uint32) uint16 {
		if limit == 0 || limit >= math.MaxUint16 {
			return math.MaxUint16
		}
		return uint16(limit)
	}

	type nodeconf struct {
		nodeID uint32
		value  any
	}

	cfg := s.Config()
	nodeconfigs := []nodeconf{
		{
			nodeID: id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead,
			value:  advertiseUint32Limit(cfg.MaxNodesPerRead()),
		},
		{
			nodeID: id.Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall,
			value:  advertiseUint32Limit(cfg.MaxMethodOperationsPerCall()),
		},
		{
			nodeID: id.Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse,
			value:  advertiseUint32Limit(cfg.MaxBrowseOperationsPerCall()),
		},
		{
			nodeID: id.Server_ServerCapabilities_MaxBrowseContinuationPoints,
			value:  advertiseUint16Limit(cfg.MaxBrowseContinuationPoints()),
		},
		{
			nodeID: id.Server_ServerCapabilities_MaxSubscriptions,
			value:  advertiseUint32Limit(cfg.MaxSubscriptions()),
		},
		{
			nodeID: id.Server_ServerCapabilities_MaxSubscriptionsPerSession,
			value:  advertiseUint32Limit(cfg.MaxSubscriptionsPerSession()),
		},
	}

	for _, cfg := range nodeconfigs {
		nodeID := ua.NewNumericNodeID(0, cfg.nodeID)
		theNode := mustHaveServerNode[types.VariableNode](nodeID, ns)
		theNode.SetValue(values.DataValueFromValue(cfg.value))
	}
}

func WireupServerStatusNodesValues(s types.Server, serverNode types.Node, ns types.NameSpace) {

	/*
		Server_ServerArray                                                                                                                                                    = 2254
		Server_NamespaceArray                                                                                                                                                 = 2255
		Server_ServerStatus_BuildInfo                                                                                                                                         = 2260
		Server_ServerStatus_BuildInfo_ProductName                                                                                                                             = 2261
		Server_ServerStatus_BuildInfo_ProductURI                                                                                                                              = 2262
		Server_ServerStatus_BuildInfo_ManufacturerName                                                                                                                        = 2263
		Server_ServerStatus_BuildInfo_SoftwareVersion                                                                                                                         = 2264
		Server_ServerStatus_BuildInfo_BuildNumber                                                                                                                             = 2265
		Server_ServerStatus_BuildInfo_BuildDate                                                                                                                               = 2266
		Server_ServiceLevel                                                                                                                                                   = 2267
		Server_ServerCapabilities                                                                                                                                             = 2268
		Server_ServerCapabilities_ServerProfileArray                                                                                                                          = 2269
		Server_ServerCapabilities_LocaleIDArray                                                                                                                               = 2271
		Server_ServerCapabilities_MinSupportedSampleRate                                                                                                                      = 2272
		Server_ServerDiagnostics                                                                                                                                              = 2274
		Server_ServerDiagnostics_ServerDiagnosticsSummary                                                                                                                     = 2275
		Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount                                                                                                     = 2276
		Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount                                                                                                 = 2277
		Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount                                                                                               = 2278
		Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount                                                                                        = 2279
		Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount                                                                                                 = 2281
		Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount                                                                                                   = 2282
		Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount                                                                                             = 2284
		Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount                                                                                            = 2285
		Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount                                                                                          = 2286
		Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount                                                                                       = 2287
		Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount                                                                                               = 2288
		Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray                                                                                                             = 2289
		Server_ServerDiagnostics_SubscriptionDiagnosticsArray                                                                                                                 = 2290
		Server_ServerDiagnostics_EnabledFlag                                                                                                                                  = 2294
		Server_VendorServerInfo                                                                                                                                               = 2295
		Server_ServerRedundancy                                                                                                                                               = 2296
	*/

	ts := time.Now()

	type nodeconf struct {
		nodeID    uint32
		valueFunc func() *ua.DataValue
	}

	nodeconfigs := []nodeconf{
		{
			id.Server_ServerStatus,
			func() *ua.DataValue {
				return values.DataValueFromValue(ua.NewExtensionObject(s.Status()))
			},
		},
		{
			id.Server_ServerStatus_State,
			func() *ua.DataValue {
				return values.DataValueFromValue(int32(s.Status().State))
			},
		},
		{
			id.Server_ServerStatus_BuildInfo_ManufacturerName,
			func() *ua.DataValue {
				return values.DataValueFromValue(s.Config().ManufacturerName())
			},
		},
		{
			id.Server_ServerStatus_BuildInfo_ProductName,
			func() *ua.DataValue {
				return values.DataValueFromValue(s.Config().ProductName())
			},
		},
		{
			id.Server_ServerStatus_BuildInfo_ProductURI,
			func() *ua.DataValue {
				return values.DataValueFromValue(s.Config().ApplicationURI())
			},
		},
		{
			id.Server_ServerStatus_BuildInfo,
			func() *ua.DataValue {
				return values.DataValueFromValue("")
			},
		},
		{
			id.Server_ServerStatus_BuildInfo_SoftwareVersion,
			func() *ua.DataValue {
				return values.DataValueFromValue(s.Config().SoftwareVersion())
			},
		},
		{
			id.Server_ServerStatus_BuildInfo_BuildNumber,
			func() *ua.DataValue {
				return values.DataValueFromValue(s.Config().SoftwareVersion())
			},
		},
		{
			id.Server_ServerStatus_BuildInfo_BuildDate,
			func() *ua.DataValue {
				return values.DataValueFromValue(ts)
			},
		},
		{
			id.Server_ServerStatus_StartTime,
			func() *ua.DataValue {
				return values.DataValueFromValue(ts.UTC())
			},
		},
		{
			id.Server_ServerStatus_CurrentTime,
			func() *ua.DataValue {
				return values.DataValueFromValue(time.Now().UTC())
			},
		},
		{
			id.Server_ServerStatus_SecondsTillShutdown,
			func() *ua.DataValue {
				return values.DataValueFromValue(int32(0))
			},
		},
		{
			id.Server_ServerStatus_ShutdownReason,
			func() *ua.DataValue {
				return values.DataValueFromValue(int32(0))
			},
		},
	}

	for _, cfg := range nodeconfigs {
		nodeID := ua.NewNumericNodeID(0, cfg.nodeID)
		theNode := mustHaveServerNode[types.VariableNode](nodeID, ns)
		theNode.SetValueFunc(cfg.valueFunc)
	}
}
