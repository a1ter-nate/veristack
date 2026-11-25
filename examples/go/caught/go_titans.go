package caught

import (
	"io"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

func badRuneOffset(s string) int {
	pos := 0
	for _, r := range s {
		pos += utf8.RuneLen(r)
	}
	return pos
}

func badPathJoin(root, raw string) string {
	return filepath.Join(root, path.Clean(raw))
}

func badDeferSelect(c io.Closer) {
	defer c.Close()
	select {}
}

func badDoubleClose(ch chan int) {
	defer close(ch)
	close(ch)
}

func badSelectSpin(jobs chan int) {
	for {
		select {
		case j := <-jobs:
			_ = j
		}
	}
}

func badCondWait(cond *sync.Cond, ready *bool) {
	if !*ready {
		cond.Wait()
	}
}

func badAtomicQuota(counter *atomic.Int64, limit int64) bool {
	if counter.Load() < limit {
		counter.Add(1)
		return true
	}
	return false
}

func badSlicePrefix(finalPath, candidateDir string) string {
	return finalPath[len(candidateDir)+1:]
}
