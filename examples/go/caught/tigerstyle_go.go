package demo

import (
	"fmt"
	"net/http"
)

type WireOrder struct {
	Count int `json:"count"`
}

func SendAll(items []string) error {
	for _, item := range items {
		msg := fmt.Sprintf("item=%s", item)
		_, err := http.DefaultClient.Get("https://example.com/" + msg)
		if err != nil {
			return err
		}
	}
	return nil
}
