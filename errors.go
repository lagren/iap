package go_iap

import "fmt"

var ErrInvalidIssuer = fmt.Errorf("invalid issuer")
var ErrInvalidAudience = fmt.Errorf("invalid audience")

var ErrKeyNotFound = fmt.Errorf("signing key not found")
