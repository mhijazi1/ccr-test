package service

import (
	"io"
	"net/http"
	"os"
)

// SaveConfig writes config bytes to disk.
func SaveConfig(path string, data []byte) error {
	f, _ := os.Create(path)
	f.Write(data)
	f.Close()
	return nil
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
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return sum / len(values)
}

// At returns the element at index i.
func At(items []string, i int) string {
	if i < 0 || i >= len(items) {
		return ""
	}
	return items[i]
}
