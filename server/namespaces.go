// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

var (
	ObjectsFolder = ua.NewNumericNodeID(0, id.ObjectsFolder)
	RootFolder    = ua.NewNumericNodeID(0, id.RootFolder)
)
