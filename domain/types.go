package domain

// Token contains token information for authenticating user.
type Token struct {
	Token string `json:"token"`

	// ExpiredIn in seconds
	ExpiredIn int `json:"expire_in"`
}
