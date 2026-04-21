package server

import (
	"context"
	"testing"
	"time"

	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChannelBrokerEnqueueMessageReturnsWhenContextCanceled(t *testing.T) {
	t.Parallel()

	broker := newChannelBroker()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	done := make(chan bool, 1)
	go func() {
		done <- broker.enqueueMessage(ctx, &uasc.MessageBody{})
	}()

	select {
	case ok := <-done:
		assert.False(t, ok)
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for enqueueMessage to return")
	}
}

func TestChannelBrokerCloseSecureChannelReturnsFalseWhenChannelMissing(t *testing.T) {
	t.Parallel()

	broker := newChannelBroker()
	assert.False(t, broker.CloseSecureChannel(t.Context(), 1))
}

func TestServerSecureChannelKeepsConfiguredEndpoint(t *testing.T) {
	t.Parallel()

	endpoint := "opc.tcp://localhost:4840/UA/Server"

	sc, err := uasc.NewServerSecureChannel(endpoint, &uacp.Conn{}, &uasc.Config{
		SecurityPolicyURI: "http://opcfoundation.org/UA/SecurityPolicy#None",
		SecurityMode:      1,
	}, make(chan error, 1), 1, 1, 1)
	require.NoError(t, err)

	assert.Equal(t, endpoint, sc.LocalEndpoint())
}
