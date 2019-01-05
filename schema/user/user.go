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

// Valid checks if the contents of the user is valid.
func (u User) Valid() bool {
	return u.ID != "" && u.Email != ""
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

// Valid checks if the contents of the credentials are valid.
func (c Credentials) Valid() bool {
	return c.Email != "" && c.Password != "" && len(c.Password) > 9
}

// Watchlist named list of stocks.
type Watchlist struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Stocks    []stock.Stock `json:"stocks"`
	CreatedAt time.Time     `json:"createdAt"`
}

// NewWatchlist creates a new watchlist.
func NewWatchlist(name string, stocks ...stock.Stock) Watchlist {
	return Watchlist{
		ID:        id.New(),
		Name:      name,
		Stocks:    stocks,
		CreatedAt: time.Now().UTC(),
	}
}

// Token holds encoded user tokens.
type Token struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// NewToken creates a new token.
func NewToken(tokenBody string, user User) Token {
	return Token{
		Token: tokenBody,
		User:  user,
	}
}

// PasswordChange describes a password change.
type PasswordChange struct {
	New      string      `json:"new"`
	Repeated string      `json:"repeated"`
	Old      Credentials `json:"old"`
}

// Valid checks if the contents of a password change are valid.
func (c PasswordChange) Valid() bool {
	return c.New != "" && c.Repeated != "" &&
		len(c.New) > 9 && c.Old.Email != "" && c.Old.Password != ""
}
