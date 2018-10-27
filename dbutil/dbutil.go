package dbutil

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/gobuffalo/packr"
	migrate "github.com/rubenv/sql-migrate"
)

// Config configuration for connection to a database.
type Config struct {
	Host     string `env:"HOST"`
	Port     string `env:"PORT" envDefault:"5432"`
	Database string `env:"DATABASE"`
	Username string `env:"USERNAME"`
	Password string `env:"PASSWORD"`
	SSLMode  bool   `env:"SSL_MODE" envDefault:"false"`
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
	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%t",
		c.Host, c.Username, c.Password, c.Database, c.Port, c.SSLMode)
}

// Migrate runs database mirgrations.
func Migrate(migrationsPath, driverName string, db *sql.DB) error {
	migrationSource := &migrate.PackrMigrationSource{
		Box: packr.NewBox(migrationsPath),
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
