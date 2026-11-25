package clean

import (
	"context"
	"io"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

func safeRuneOffset(s string) int {
	pos := 0
	for pos < len(s) {
		_, width := utf8.DecodeRuneInString(s[pos:])
		pos += width
	}
	return pos
}

func safePathJoin(root, raw string) string {
	if strings.Contains(raw, "\\") {
		return root
	}
	return filepath.Join(root, path.Clean(raw))
}

func safeShutdown(ctx context.Context, c io.Closer) {
	defer c.Close()
	<-ctx.Done()
}

func safeSingleClose(ch chan int, once *sync.Once) {
	defer once.Do(func() { close(ch) })
	once.Do(func() { close(ch) })
}

func safeSelectLoop(jobs chan int) {
	for {
		select {
		case j, ok := <-jobs:
			if !ok {
				jobs = nil
				continue
			}
			_ = j
		}
	}
}

func safeCondWait(cond *sync.Cond, ready *bool) {
	for !*ready {
		cond.Wait()
	}
}

func safeAtomicQuota(counter *atomic.Int64, limit int64) bool {
	for {
		cur := counter.Load()
		if cur >= limit {
			return false
		}
		if counter.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func safeSlicePrefix(finalPath, candidateDir string) string {
	if len(finalPath) > len(candidateDir) {
		return finalPath[len(candidateDir)+1:]
	}
	return ""
}
