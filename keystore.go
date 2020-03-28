package go_iap

import (
	"crypto/ecdsa"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

type KeyLoader interface {
	Load(kid string) (*ecdsa.PublicKey, error)
}

type googleKeyLoader struct {
	keys map[string]*ecdsa.PublicKey
	sync.Mutex
}

func (kl *googleKeyLoader) Load(kid string) (*ecdsa.PublicKey, error) {
	kl.Lock()
	defer kl.Unlock()

	if key, found := kl.keys[kid]; found {
		return key, nil
	}

	return nil, ErrKeyNotFound
}

func (kl *googleKeyLoader) loadKeys() error {
	resp, err := http.Get("https://www.gstatic.com/iap/verify/public_key")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var keyStrings map[string]string
	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, &keyStrings); err != nil {
		return err
	}

	parsedKeys := make(map[string]*ecdsa.PublicKey)

	for kid, s := range keyStrings {
		key, err := jwt.ParseECPublicKeyFromPEM([]byte(s))
		if err != nil {
			return err
		}

		parsedKeys[kid] = key
	}

	kl.Lock()
	defer kl.Unlock()

	kl.keys = parsedKeys

	return nil
}

func (kl *googleKeyLoader) updater() {
	for {
		time.Sleep(time.Hour)

		if err := kl.loadKeys(); err != nil {
			log.Println("Could not refresh Google IAP signing keys:", err)
		}
	}
}

func NewKeyLoader() (KeyLoader, error) {
	keyloader := &googleKeyLoader{}

	go keyloader.updater() // Poll for new keys

	return keyloader, nil
}

type staticKeyLoader struct {
	publicKey *ecdsa.PublicKey
}

func (kl staticKeyLoader) Load(kid string) (*ecdsa.PublicKey, error) {
	return kl.publicKey, nil
}
