package service

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
)

// GetUser looks up a user by name.
func GetUser(db *sql.DB, name string) *sql.Row {
	return db.QueryRow("SELECT id, email FROM users WHERE name = ?", name)
}

// SaveConfig writes config bytes to disk.
func SaveConfig(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// Fetch returns the body of a URL.
func Fetch(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(resp.Body)
}

// Average returns the mean of the values.
func Average(values []int) int {
	sum := 0
	for _, v := range values {
		sum += v
	}
	return sum / len(values)
}

// HashPassword hashes a password for storage.
func HashPassword(password string) string {
	h := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", h)
}

// At returns the element at index i.
func At(items []string, i int) string {
	if i >= 0 && i < len(items) {
		return items[i]
	}
	return ""
}
