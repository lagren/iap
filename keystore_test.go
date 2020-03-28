package go_iap

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGoogleKeyLoader(t *testing.T) {
	keyLoader := &googleKeyLoader{}

	err := keyLoader.loadKeys()
	require.NoError(t, err)

	require.NotEmpty(t, keyLoader.keys)

	for kid, _ := range keyLoader.keys {
		key, err := keyLoader.Load(kid)
		require.NoError(t, err)
		require.NotNil(t, key)
	}

	key, err := keyLoader.Load("non-existent")
	require.EqualError(t, err, ErrKeyNotFound.Error())
	require.Nil(t, key)
}
