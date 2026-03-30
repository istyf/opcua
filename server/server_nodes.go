package server

import (
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/attrs"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

func CurrentTimeNode() types.Node {
	return node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_CurrentTime),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("CurrentTime")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(time.Now()) },
	)
}

func NamespacesNode(s *Server) types.Node {
	return node.NewNode(
		ua.NewNumericNodeID(0, id.Server_NamespaceArray),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("Namespaces")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassObject)),
		},
		nil,
		func() *ua.DataValue {
			n := s.Namespaces()
			ns := make([]string, len(n))
			for i := range ns {
				ns[i] = n[i].Name()
			}
			return values.DataValueFromValue(ns)
		},
	)
}

func ServerCapabilitiesNodes(s *Server) []types.Node {
	var nodes []types.Node
	nodes = append(nodes, node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("MaxNodesPerRead")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(s.cfg.cap.OperationalLimits.MaxNodesPerRead) },
	))
	return nodes
}

func RootNode() types.Node {
	return node.NewNode(
		ua.NewNumericNodeID(0, id.RootFolder),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  values.DataValueFromValue(attrs.NodeClass(ua.NodeClassObject)),
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("Root")),
			ua.AttributeIDDataType:   values.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.DataTypesFolder)),
		},
		nil,
		nil,
	)
}

func ServerStatusNodes(s *Server, serverNode types.Node) []types.Node {

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

	sStatus := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("Status")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(ua.NewExtensionObject(s.Status())) },
	)

	sState := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_State),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("ServerStatus")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(int32(s.Status().State)) },
	)
	mName := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_ManufacturerName),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("ManufacturerName")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(s.cfg.manufacturerName) },
	)
	pName := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_ProductName),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("ProductName")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(s.cfg.productName) },
	)

	pURI := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_ProductURI),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("ProductURI")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(s.cfg.applicationURI) },
	)

	bInfo := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("BuildInfo")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue("") },
	)
	sVersion := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_SoftwareVersion),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("SoftwareVersion")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(s.cfg.softwareVersion) },
	)

	bNumber := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_BuildNumber),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("BuildNumber")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(s.cfg.softwareVersion) },
	)

	ts := time.Now()
	bDate := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_BuildDate),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("BuildDate")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(ts) },
	)
	timeStart := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_StartTime),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("StartTime")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(ts) },
	)
	timeCurrent := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_CurrentTime),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("CurrentTime")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(time.Now()) },
	)

	//Server_ServerStatus_SecondsTillShutdown                                                                                                                               = 2992
	//Server_ServerStatus_ShutdownReason                                                                                                                                    = 2993
	sTillShutdown := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_SecondsTillShutdown),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("SecondsTillShutdown")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(int32(0)) },
	)
	sReason := node.NewNode(
		ua.NewNumericNodeID(0, id.Server_ServerStatus_ShutdownReason),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("ShutdownReason")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(int32(0)) },
	)

	nodes := []types.Node{sState, mName, pName, pURI, sVersion, bNumber, bDate, timeStart, timeCurrent, bInfo, sTillShutdown, sReason}
	for i := range nodes {
		sStatus.AddRef(refs.NewHasComponentRefDesc(nodes[i]))
	}
	serverNode.AddRef(refs.NewHasComponentRefDesc(sStatus))

	nodes = append(nodes, sStatus)

	return nodes
}
