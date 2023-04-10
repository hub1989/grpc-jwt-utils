package jwks

import (
	"context"
	"github.com/lestrrat-go/jwx/jwk"
	"os"
)

// DefaultKeySet fetches a jwk.Set from an environment variable `JWKS_URI`
// The easiest way to find the jwks uri is to use the `.well-known/openid-configuration` endpoint provided by your IDP
func DefaultKeySet(ctx context.Context) (jwk.Set, error) {
	return jwk.Fetch(ctx, os.Getenv("JWKS_URI"))
}
