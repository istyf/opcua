package context

import (
	"context"
	"iter"

	"github.com/gopcua/opcua/ua"
)

type srvCtxKeyType struct{}

var srvCtxKey = srvCtxKeyType{}

type LocalizedTextReader func([]*ua.LocalizedText) *ua.LocalizedText

type srvctx struct {
	methodID         string
	methodName       string
	methodObjectID   string
	methodObjectName string

	serviceSet  string
	serviceName string

	preferedLocales []string
}

var defaultLocales = []string{"en"}

func load(ctx context.Context) *srvctx {
	sc, ok := ctx.Value(srvCtxKey).(*srvctx)

	if !ok {
		return &srvctx{
			preferedLocales: defaultLocales,
		}
	}

	return sc
}

func store(ctx context.Context, sc *srvctx) context.Context {
	return context.WithValue(ctx, srvCtxKey, sc)
}

func WithMethodCall(ctx context.Context, objectID, objectName, methodID, methodName string) context.Context {
	sc := load(ctx)

	sc.methodID = methodID
	sc.methodName = methodName
	sc.methodObjectID = objectID
	sc.methodObjectName = objectName

	return store(ctx, sc)
}

func MethodID(ctx context.Context) string {
	return load(ctx).methodID
}

func MethodName(ctx context.Context) string {
	return load(ctx).methodName
}

func MethodObjectID(ctx context.Context) string {
	return load(ctx).methodObjectID
}

func MethodObjectName(ctx context.Context) string {
	return load(ctx).methodObjectName
}

func WithPreferedLocales(ctx context.Context, locales []string) context.Context {
	sc := load(ctx)

	if len(locales) == 0 {
		locales = defaultLocales
	}

	sc.preferedLocales = locales
	return store(ctx, sc)
}

func PreferedLocalesFromContext(ctx context.Context) iter.Seq[string] {
	locales := load(ctx).preferedLocales
	return func(yield func(string) bool) {
		for _, loc := range locales {
			if !yield(loc) {
				return
			}
		}
	}
}

func WithServiceSetAndName(ctx context.Context, set, name string) context.Context {
	sc := load(ctx)

	sc.serviceName = name
	sc.serviceSet = set

	return store(ctx, sc)
}

func ServiceSet(ctx context.Context) string {
	return load(ctx).serviceSet
}

func ServiceName(ctx context.Context) string {
	return load(ctx).serviceName
}
