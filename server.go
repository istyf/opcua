// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

// Server is a high-level OPC-UA Server
type Server struct {
	EndpointURL string

	// conn *uasc.ServerConn
}

func (s *Server) Open() error {
	return nil
}

func (s *Server) Close() error {
	return nil
}
