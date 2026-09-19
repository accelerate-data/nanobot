package gormdsn

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewDBFromDSN(dsn string) (*gorm.DB, error) {
	return newDBFromDSN(dsn, os.Stdout)
}

// newDBFromDSN opens the database identified by dsn, writing GORM's query log
// to logOutput. Bound parameter values are never logged: session configs carry
// decrypted MCP credentials (bearer tokens, OAuth client secrets), and GORM
// interpolates every bound value into the SQL it logs unless the logger is
// parameterized. See newLogger.
func newDBFromDSN(dsn string, logOutput io.Writer) (*gorm.DB, error) {
	var dialector gorm.Dialector

	switch {
	case strings.HasPrefix(dsn, "sqlite:") || strings.HasSuffix(dsn, ".db") || strings.Contains(dsn, ":memory:"):
		if sqliteDSN, ok := strings.CutPrefix(dsn, "sqlite://"); ok {
			dsn = sqliteDSN
		} else {
			dsn = strings.TrimPrefix(dsn, "sqlite:")
		}
		dialector = sqlite.Open(dsn)
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		dialector = postgres.Open(dsn)
	case strings.HasPrefix(dsn, "mysql://") || strings.Contains(dsn, "@tcp("):
		dsn = strings.TrimPrefix(dsn, "mysql://")
		dialector = mysql.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported database type in DSN: %s", dsn)
	}

	return gorm.Open(dialector, &gorm.Config{
		Logger: newLogger(logOutput),
	})
}

// newLogger returns a GORM logger that deliberately omits bound parameter
// values from every log line (slow queries and errors alike). GORM only
// substitutes values into the logged SQL when its logger implements
// logger.ParamsFilter without ParameterizedQueries set, so setting the flag
// keeps the query shape and timing while leaving the values as placeholders.
func newLogger(logOutput io.Writer) logger.Interface {
	return logger.New(log.New(logOutput, "\r\n", log.LstdFlags), logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		Colorful:                  true,
		ParameterizedQueries:      true,
	})
}
