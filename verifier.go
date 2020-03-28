package go_iap

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type verifier struct {
	keys     KeyLoader
	audience string
}

func (v *verifier) keyFunc(token *jwt.Token) (interface{}, error) {
	if token.Method != jwt.SigningMethodES256 {
		return nil, fmt.Errorf("%s is not a supported signing method for Google IAP", token.Method.Alg())
	}

	if !token.Claims.(*GoogleIAPToken).VerifyIssuer(googleIAPIssuer, true) {
		return nil, ErrInvalidIssuer
	}

	if !token.Claims.(*GoogleIAPToken).VerifyAudience(v.audience, true) {
		return nil, ErrInvalidAudience
	}

	return v.keys.Load(token.Header["kid"].(string))
}

func VerifyJWT(token string, keys KeyLoader, audience string) (*GoogleIAPToken, error) {
	return nil, nil
}
