package user

import (
	"time"

	"github.com/mimir-news/pkg/id"

	"github.com/mimir-news/pkg/schema/stock"
)

// User holds data about an applicatoin user.
type User struct {
	ID         string      `json:"id"`
	Email      string      `json:"email"`
	Watchlists []Watchlist `json:"watchlists"`
	CreatedAt  time.Time   `json:"createdAt"`
}

// New creates a new user.
func New(email string, watchlists []Watchlist) User {
	return User{
		ID:         id.New(),
		Email:      email,
		Watchlists: watchlists,
		CreatedAt:  time.Now().UTC(),
	}
}

// Credentials login credentials provided by a user.
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Watchlist named list of stocks.
type Watchlist struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Stocks    []stock.Stock `json:"stocks"`
	CreatedAt time.Time     `json:"createdAt"`
}

// Token holds encoded user tokens.
type Token struct {
	Token string `json:"name"`
}

// NewToken creates a new token.
func NewToken(tokenBody string) Token {
	return Token{
		Token: tokenBody,
	}
}
