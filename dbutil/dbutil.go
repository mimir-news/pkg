package dbutil

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"

	migrate "github.com/rubenv/sql-migrate"
)

// Common errors.
var (
	ErrFailedInsert = errors.New("insert failed")
	ErrNotConnected = errors.New("not connected to database")
)

// Querier interface for quering rows.
type Querier interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

// Config configuration for connection to a database.
type Config struct {
	Host            string
	Port            string
	Database        string
	Username        string
	Password        string
	SSLMode         string
	BinaryParamters string
}

// MustGetConfig gets database config from environment and
// fails if required values are missing.
func MustGetConfig(namespace string) Config {
	return Config{
		Host:            mustGetenv(namespace + "_HOST"),
		Port:            getenv(namespace+"_PORT", "5432"),
		Database:        mustGetenv(namespace + "_NAME"),
		Username:        mustGetenv(namespace + "_USERNAME"),
		Password:        mustGetenv(namespace + "_PASSWORD"),
		SSLMode:         getenv(namespace+"_SSL_MODE", "disable"),
		BinaryParamters: getenv(namespace+"_BINARY_PARAMETERS", "no"),
	}
}

// ConnectPostgres connects to a postgres instance.
func (c Config) ConnectPostgres() (*sql.DB, error) {
	db, err := sql.Open("postgres", c.PgDSN())
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	return db, err
}

// PgDSN creates datasource name for compliant with whats expected by postgres.
func (c Config) PgDSN() string {
	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s binary_parameters=%s",
		c.Host, c.Username, c.Password, c.Database, c.Port, c.SSLMode, c.BinaryParamters)
}

// Migrate runs database mirgrations.
func Migrate(migrationsPath, driverName string, db *sql.DB) error {
	migrationSource := &migrate.FileMigrationSource{
		Dir: migrationsPath,
	}
	migrate.SetTable("schema_version")

	migrations, err := migrationSource.FindMigrations()
	if err != nil {
		return err
	}

	if len(migrations) == 0 {
		return errors.New("Missing database migrations")
	}

	_, err = migrate.Exec(db, driverName, migrationSource, migrate.Up)
	if err != nil {
		return fmt.Errorf("Error applying database migrations: %s", err)
	}
	return nil
}

// AssertRowsAffected check that the expected number of rows where affected by a database operation.
func AssertRowsAffected(res sql.Result, expected int64, missmatchErr error) error {
	rowsUpdated, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if rowsUpdated != expected {
		return missmatchErr
	}
	return nil
}

// RollbackTx rolls back a transaction and logs any errors that occured.
func RollbackTx(tx *sql.Tx) {
	err := tx.Rollback()
	if err != nil {
		log.Println(err)
	}
}

// IsConnected checks that the client is connected to the database.
func IsConnected(db *sql.DB) error {
	rows, err := db.Query("SELECT 1")
	if err != nil {
		log.Println("ERROR -", err)
		return ErrNotConnected
	}
	defer rows.Close()
	return nil
}

func mustGetenv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("No value for key: %s\n", key)
	}

	return val
}

func getenv(key, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}

	return val
}
