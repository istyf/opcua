package services

import (
	"context"

	"github.com/gopcua/opcua/server/types"
)

const nilAuthorizationContextDecoratorPanic = "server authorization context decorator returned nil context"

func decorateAuthorizationContext(ctx context.Context, cfg types.ServerConfig, session types.Session) context.Context {
	if cfg == nil || session == nil {
		return ctx
	}

	decorator := cfg.AuthorizationContextDecorator()
	if decorator == nil {
		return ctx
	}

	decoratedCtx := decorator(ctx, session.AuthenticatedUser())
	if decoratedCtx == nil {
		panic(nilAuthorizationContextDecoratorPanic)
	}

	return decoratedCtx
}
