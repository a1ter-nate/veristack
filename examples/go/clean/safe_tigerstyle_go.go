package demo

import (
	"net/http"
	"time"
)

type WireOrder struct {
	Count uint32 `json:"count"`
}

func NewHttpClient(timeoutMsMax int64) *http.Client {
	return &http.Client{Timeout: time.Duration(timeoutMsMax) * time.Millisecond}
}
