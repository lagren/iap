package go_iap

type contextKey string

var (
	EmailContextKey  = contextKey("email")
	UserIDContextKey = contextKey("userID")
)

const googleIAPIssuer = "https://cloud.google.com/iap"
