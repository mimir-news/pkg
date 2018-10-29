package news

import (
	"fmt"
	"strings"
	"time"

	"github.com/mimir-news/pkg/id"
)

// Article contains article info.
type Article struct {
	ID             string    `json:"id"`
	URL            string    `json:"url"`
	Title          string    `json:"title"`
	Body           string    `json:"body"`
	Keywords       []string  `json:"keywords"`
	ReferenceScore float64   `json:"referenceScore"`
	ArticleDate    time.Time `json:"articleDate"`
	CreatedAt      time.Time `json:"createdAt"`
}

// NewArticle creates a new article.
func NewArticle(URL string) Article {
	return Article{
		ID:  id.New(),
		URL: URL,
	}
}

func (a Article) String() string {
	return fmt.Sprintf(
		"Article(id=%s url=%s title=%s keywords=[%s] referenceScore=%f)",
		a.ID, a.URL, a.Title, strings.Join(a.Keywords, ","), a.ReferenceScore)
}

// RankObject contains info to scrape and rank an article.
type RankObject struct {
	URLs     []string  `json:"urls"`
	Subjects []Subject `json:"subjects"`
	Referer  Referer   `json:"referer"`
	Language string    `json:"language"`
}

func (ro RankObject) String() string {
	urls := strings.Join(ro.URLs, ",")
	subjects := joinSubjects(ro.Subjects)

	return fmt.Sprintf("RankObject(urls=[%s] subjects=[%s], author=%s, language=%s)",
		urls, subjects, ro.Referer, ro.Language)
}

// Referer contains info about an article refererer.
type Referer struct {
	ID            string `json:"id"`
	ExternalID    string `json:"externalId"`
	FollowerCount int64  `json:"followerCount"`
	ArticleID     string `json:"articleId"`
}

func (r Referer) String() string {
	return fmt.Sprintf(
		"Referer(id=%s externalId=%s followerCount=%d articleId=%s)",
		r.ID, r.ExternalID, r.FollowerCount, r.ArticleID)
}

// Subject subject which to look for in an article.
type Subject struct {
	ID        string  `json:"id"`
	Symbol    string  `json:"symbol"`
	Name      string  `json:"name"`
	Score     float64 `json:"score"`
	ArticleID string  `json:"articleId"`
}

func (s Subject) String() string {
	return fmt.Sprintf(
		"Subject(id=%s symbol=%s name=%s score=%f articleId=%s)",
		s.ID, s.Symbol, s.Name, s.Score, s.ArticleID)
}

// ScrapeTarget article info needed to scrape and score an article.
type ScrapeTarget struct {
	URL       string    `json:"url"`
	Subjects  []Subject `json:"subjects"`
	Referer   Referer   `json:"referer"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	ArticleID string    `json:"articleId"`
}

func (s ScrapeTarget) String() string {
	return fmt.Sprintf(
		"ScrapeTarget(url=%s subjects=[%s] referer=%s title=%s body=%s articleId=%s)",
		s.URL, joinSubjects(s.Subjects), s.Referer, s.Title, s.Body, s.ArticleID)
}

// ScrapedArticle result of scraping and scoring an article.
type ScrapedArticle struct {
	Article  Article   `json:"article"`
	Subjects []Subject `json:"subjects"`
	Referer  Referer   `json:"referer"`
}

func (s ScrapedArticle) String() string {
	return fmt.Sprintf(
		"ScrapedArticle(article=%s subjects=[%s] referer=%s)",
		s.Article, joinSubjects(s.Subjects), s.Referer)
}

func joinSubjects(subjects []Subject) string {
	subjectList := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		subjectList = append(subjectList, subject.String())
	}
	return strings.Join(subjectList, ",")
}
