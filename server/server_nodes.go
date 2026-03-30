package server

import (
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

func NamespacesNode(s *Server) types.VariableNode {
	return node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_NamespaceArray)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "NamespaceArray"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.String)),
		node.WithValueRank(1),
		node.WithDataValue(
			func() *ua.DataValue {
				n := s.Namespaces()
				ns := make([]string, len(n))
				for i := range ns {
					ns[i] = n[i].Name()
				}
				return values.DataValueFromValue(ns)
			}),
	)
}

func ServerCapabilitiesNodes(s *Server) []types.VariableNode {
	var nodes []types.VariableNode
	nodes = append(nodes, node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "MaxNodesPerRead"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.UInt32)),
		node.WithDataValue(
			func() *ua.DataValue {
				return values.DataValueFromValue(
					s.cfg.cap.OperationalLimits.MaxNodesPerRead,
				)
			}),
	))
	return nodes
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

	sStatus := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "Status"}),
		),
		node.WithDataType(ua.NewExtensionObject(s.Status()).TypeID.NodeID),
		node.WithDataValue(
			func() *ua.DataValue {
				return values.DataValueFromValue(ua.NewExtensionObject(s.Status()))
			}),
	)

	sState := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_State)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "ServerStatus"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.Int32)),
		node.WithDataValue(
			func() *ua.DataValue {
				return values.DataValueFromValue(int32(s.Status().State))
			}),
	)
	mName := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_ManufacturerName)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "ManufacturerName"}),
		),
		node.WithValue(s.cfg.manufacturerName),
	)
	pName := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_ProductName)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "ProductName"}),
		),
		node.WithValue(s.cfg.productName),
	)

	pURI := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_ProductURI)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "ProductURI"}),
		),
		node.WithValue(s.cfg.applicationURI),
	)

	bInfo := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BuildInfo"}),
		),
		node.WithValue(""),
	)
	sVersion := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_SoftwareVersion)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "SoftwareVersion"}),
		),
		node.WithValue(s.cfg.softwareVersion),
	)

	bNumber := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_BuildNumber)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BuildNumber"}),
		),
		node.WithValue(s.cfg.softwareVersion),
	)

	ts := time.Now()
	bDate := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_BuildInfo_BuildDate)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BuildDate"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.DateTime)),
		node.WithDataValue(values.DataValueFromValue(ts)),
	)
	timeStart := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_StartTime)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "StartTime"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.UtcTime)),
		node.WithDataValue(values.DataValueFromValue(ts.UTC())),
	)
	timeCurrent := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_CurrentTime)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "CurrentTime"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.UtcTime)),
		node.WithDataValue(
			func() *ua.DataValue {
				return values.DataValueFromValue(time.Now().UTC())
			}),
	)

	//Server_ServerStatus_SecondsTillShutdown                                                                                                                               = 2992
	//Server_ServerStatus_ShutdownReason                                                                                                                                    = 2993
	sTillShutdown := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_SecondsTillShutdown)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "SecondsTillShutdown"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.Int32)),
		node.WithDataValue(
			func() *ua.DataValue {
				return values.DataValueFromValue(int32(0))
			}),
	)
	sReason := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.Server_ServerStatus_ShutdownReason)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "ShutdownReason"}),
		),
		node.WithDataType(ua.NewNumericNodeID(0, id.Int32)),
		node.WithDataValue(
			func() *ua.DataValue {
				return values.DataValueFromValue(int32(0))
			}),
	)

	nodes := []types.Node{sState, mName, pName, pURI, sVersion, bNumber, bDate, timeStart, timeCurrent, bInfo, sTillShutdown, sReason}

	sStatus.AddComponents(nodes...)
	serverNode.AddComponent(sStatus)

	return append(nodes, sStatus)
}
