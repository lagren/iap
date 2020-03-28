package go_iap

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
)

func New(requiredAudience string) *iap {
	i := &iap{
		audience: requiredAudience,
		certs:    map[string]string{},
	}

	err := i.refreshCerts()

	if err != nil {
		fmt.Printf("could not refresh certificates: %s\n", err)
	}

	return i
}

type iap struct {
	audience string
	certs    map[string]string
}

func (i *iap) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		assertion := r.Header.Get("X-Goog-IAP-JWT-Assertion")

		if assertion == "" {
			log.Print("No X-Goog-IAP-JWT-Assertion header found")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		email, userID, err := i.validate(assertion)

		if err != nil {
			log.Printf("could not validate assertion: %s\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), EmailContextKey, email)
		ctx = context.WithValue(ctx, UserIDContextKey, userID)

		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (i *iap) validate(assertion string) (email, userID string, err error) {
	certs := i.certs
	token, err := jwt.Parse(assertion, func(token *jwt.Token) (i interface{}, err error) {
		keyID := token.Header["kid"].(string)

		_, ok := token.Method.(*jwt.SigningMethodECDSA)

		if !ok {
			return nil, fmt.Errorf("unexpected signing method. expected SigningMethodECDSA")
		}

		cert, found := certs[keyID]

		if !found {
			return nil, fmt.Errorf("could not find certificate with id %s", keyID)
		}

		return jwt.ParseECPublicKeyFromPEM([]byte(cert))
	})

	if err != nil {
		return "", "", fmt.Errorf("could not validate token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return "", "", fmt.Errorf("could not parse claims")
	}

	a, found := claims["aud"]

	if !found || a == "" {
		return "", "", fmt.Errorf("could not find aud in token")
	}

	if a != i.audience {
		return "", "", fmt.Errorf("wrong audience. got %s expected %s", a, i.audience)
	}

	return claims["email"].(string), claims["sub"].(string), nil
}

func (i *iap) refreshCerts() error {
	resp, err := http.Get("https://www.gstatic.com/iap/verify/public_key")

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not fetch certificates: %s", resp.Status)
	}

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return fmt.Errorf("could not read certificate payload: %s", err)
	}

	var certs map[string]string

	err = json.Unmarshal(b, &certs)

	if err != nil {
		return fmt.Errorf("could not parse certificate payload: %s", err)
	}

	i.certs = certs

	return nil
}

type GoogleIAPToken struct {
	AccountDomain string `json:"hd,omitempty"`
	jwt.StandardClaims
}
