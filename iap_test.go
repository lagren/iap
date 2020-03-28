package go_iap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMiddleware(t *testing.T) {

}

func TestVerifier(t *testing.T) {
	key := createECDSAKey()
	audience := "/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID"

	verify := verifier{
		audience: "/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID",
		keys:     staticKeyLoader{&key.PublicKey},
	}

	var table = []struct {
		name     string
		audience string
		issuer   string
		valid    bool
		err      error
	}{
		{
			"valid",
			audience,
			googleIAPIssuer,
			true,
			nil,
		},
		{
			"invalid_issuer",
			audience,
			"bar",
			false,
			ErrInvalidIssuer,
		},
		{
			"invalid_audience",
			"foo",
			googleIAPIssuer,
			false,
			ErrInvalidAudience,
		},
	}

	for _, test := range table {
		t.Run(test.name, func(t *testing.T) {
			tokenString := createIAPToken(key, test.audience, test.issuer)

			token, err := jwt.ParseWithClaims(tokenString, &GoogleIAPToken{}, verify.keyFunc)

			if test.valid {
				require.NoError(t, err)
				require.True(t, token.Valid)
			} else {
				require.EqualError(t, err, test.err.Error())
			}
		})
	}

}

func createIAPToken(key *ecdsa.PrivateKey, audience, issuer string) string {
	claims := GoogleIAPToken{
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Audience:  audience,
			Issuer:    issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "foo"
	tokenString, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	return tokenString
}

func createECDSAKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return privateKey
}
