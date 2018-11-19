package user

import (
	"time"

	"github.com/mimir-news/pkg/schema/stock"
)

// User holds data about an applicatoin user.
type User struct {
	ID         string      `json:"id"`
	Email      string      `json:"email"`
	Watchlists []Watchlist `json:"watchlists"`
	CreatedAt  time.Time   `json:"createdAt"`
}

// Credentials login credentials provided by a user.
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Watchlist named list of stocks.
type Watchlist struct {
	Name      string        `json:"name"`
	Stocks    []stock.Stock `json:"stocks"`
	CreatedAt time.Time     `json:"createdAt"`
}
