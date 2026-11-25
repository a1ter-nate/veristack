package caught

import (
	"io"
	"math"
	"net/http"
	"strings"
)

type DialError struct{ msg string }

func (e DialError) Error() string { return e.msg }

func badHttpGet(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

func badRead(r io.Reader, buf []byte) {
	_, _ = io.ReadFull(r, buf)
}

func badErrAssert(proxyErr error) bool {
	_, ok := proxyErr.(DialError)
	return ok
}

func badAuthzPath(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.RawPath, "/admin") {
		w.WriteHeader(http.StatusForbidden)
	}
}

func badNanCmp(v float64) bool {
	return v == math.NaN()
}
