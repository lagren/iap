package go_iap

type contextKey string

var (
	EmailContextKey  = contextKey("email")
	UserIDContextKey = contextKey("userID")
)
