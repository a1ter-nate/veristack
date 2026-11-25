package clean

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"path"
	"strings"
	"time"
)

type DialError struct{ msg string }

func (e DialError) Error() string { return e.msg }

func safeHttpGet(ctx context.Context, url string) (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func safeRead(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

func safeErrAs(proxyErr error) bool {
	var dialErr DialError
	return errors.As(proxyErr, &dialErr)
}

func safeAuthzPath(w http.ResponseWriter, r *http.Request) {
	cleanPath := path.Clean(r.URL.Path)
	if strings.HasPrefix(cleanPath, "/admin") {
		w.WriteHeader(http.StatusForbidden)
	}
}

func safeNanCheck(v float64) bool {
	return math.IsNaN(v)
}
