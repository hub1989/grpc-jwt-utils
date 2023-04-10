package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"strings"
)

type Service interface {
	GetKey(token *jwt.Token) (interface{}, error)
	LoadUserInfoREST(ctx context.Context, token string) (interface{}, error)
	GetClaimsFromRequest(token *jwt.Token) jwt.MapClaims
	AuthenticateFromContext(ctx context.Context) (*jwt.Token, error)
	GetSubAndRolesFromRequest(token *jwt.Token) (string, []string)
	AuthenticateForUser(ctx context.Context, userPid string, roleName string) error
}

type DefaultJwtAuthenticationService struct {
	KeySet           jwk.Set
	UserInfoEndpoint string
	*http.Client
	RoleClaimName string
}

// GetKey get key used to sign the JWT
func (j DefaultJwtAuthenticationService) GetKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have a key ID in the kid field")
	}

	key, found := j.KeySet.LookupKeyID(keyID)

	if !found {
		return nil, fmt.Errorf("unable to find key %q", keyID)
	}

	var pubkey interface{}
	if err := key.Raw(&pubkey); err != nil {
		return nil, fmt.Errorf("unable to get the public key. Error: %s", err.Error())
	}

	return pubkey, nil
}

// GetClaimsFromRequest get all claims from a jwt token
func (j DefaultJwtAuthenticationService) GetClaimsFromRequest(token *jwt.Token) jwt.MapClaims {
	return token.Claims.(jwt.MapClaims)
}

// AuthenticateFromContext checks the context for authorization
// validates the token
func (j DefaultJwtAuthenticationService) AuthenticateFromContext(ctx context.Context) (*jwt.Token, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	token := values[0]

	jwtToken, err := jwt.Parse(token, j.GetKey)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return jwtToken, nil
}

// GetSubAndRolesFromRequest get a user's sub and the claim to be used as roles
// cognito uses something like "cognito:groups" while keycloak uses something like "roles"
func (j DefaultJwtAuthenticationService) GetSubAndRolesFromRequest(token *jwt.Token) (string, []string) {
	claims := j.GetClaimsFromRequest(token)
	sub := claims["sub"].(string)

	roles := claims[j.RoleClaimName].([]interface{})
	roleStrings := make([]string, len(roles))

	for i, v := range roles {
		roleStrings[i] = v.(string)
	}

	return sub, roleStrings
}

// HasRoleAccess checks if a list of roles contains a given role
func (j DefaultJwtAuthenticationService) HasRoleAccess(roles []string, roleName string) bool {
	for _, g := range roles {
		if strings.EqualFold(g, roleName) {
			return true
		}
	}

	return false
}

// AuthenticateForUser checks if the user's token(passed in a context) contains the required role for an operation
func (j DefaultJwtAuthenticationService) AuthenticateForUser(ctx context.Context, userPid string, roleName string) error {
	token, err := j.AuthenticateFromContext(ctx)
	if err != nil {
		return err
	}

	sub, roles := j.GetSubAndRolesFromRequest(token)
	if !j.HasRoleAccess(roles, roleName) {
		return status.Error(codes.PermissionDenied, "you do not have the right permission for this operation")
	}

	if sub != userPid {
		return status.Error(codes.PermissionDenied, "you do not have the right permission for this operation")
	}

	return nil
}

// LoadUserInfoREST load user information from a jwt token.
// note that the token needs to have the openid scope
func (j DefaultJwtAuthenticationService) LoadUserInfoREST(ctx context.Context, token string) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.UserInfoEndpoint, nil)

	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	res, err := j.Client.Do(req)

	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, errors.New("could not get user info -- see reason " + res.Status)
	}

	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	var userInfo interface{}
	err = json.Unmarshal(data, &userInfo)

	return userInfo, nil
}
