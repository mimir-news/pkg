package stock

// Stock holds data describing a stock.
type Stock struct {
	Name        string `json:"name"`
	Symbol      string `json:"symbol"`
	Description string `json:"description"`
}
