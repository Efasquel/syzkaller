// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package log provides functionality similar to standard log package with some extensions:
//   - verbosity levels
//   - global verbosity setting that can be used by multiple packages
//   - ability to disable all output
//   - ability to cache recent output in memory
package log

import (
	"bytes"
	"flag"
	"fmt"
	golog "log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	flagV          = flag.Int("vv", 0, "verbosity")
	mu             sync.Mutex
	cacheMem       int
	cacheMaxMem    int
	cachePos       int
	cacheEntries   []string
	cachingEnabled atomic.Bool
	instanceName   string
	prependTime    = true // for testing
	logFileLogger  *golog.Logger
)

// EnableLogCaching enables in memory caching of log output.
// Caches up to maxLines, but no more than maxMem bytes.
// Cached output can later be queried with CachedOutput.
func EnableLogCaching(maxLines, maxMem int) {
	mu.Lock()
	defer mu.Unlock()
	if cacheEntries != nil {
		Fatalf("log caching is already enabled")
	}
	if maxLines < 1 || maxMem < 1 {
		panic("invalid maxLines/maxMem")
	}
	cacheMaxMem = maxMem
	cacheEntries = make([]string, maxLines)
	cachingEnabled.Store(true)
}

// Retrieves cached log output.
func CachedLogOutput() string {
	mu.Lock()
	defer mu.Unlock()
	buf := new(bytes.Buffer)
	for i := range cacheEntries {
		pos := (cachePos + i) % len(cacheEntries)
		if cacheEntries[pos] == "" {
			continue
		}
		buf.WriteString(cacheEntries[pos])
		buf.Write([]byte{'\n'})
	}
	return buf.String()
}

// If the name is set, it will be displayed for all logs.
func SetName(name string) {
	instanceName = name
}

// SetLogFile opens path (append/create) and mirrors all log output there.
// A run separator with the current time and command line is written to the file first.
func SetLogFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "\n=== run started %v | cmd: %v ===\n",
		time.Now().Format("2006/01/02 15:04:05"), strings.Join(os.Args, " "))
	mu.Lock()
	logFileLogger = golog.New(f, "", golog.LstdFlags)
	mu.Unlock()
	return nil
}

// V reports whether verbosity at the call site is at least the requested level.
// See https://pkg.go.dev/github.com/golang/glog#V for details.
func V(level int) bool {
	return level <= *flagV
}

func Log(v int, msg string) {
	Logf(v, "%v", msg)
}

func Logf(v int, msg string, args ...any) {
	writeMessage(v, "", msg, args...)
}

func Error(err error) {
	Errorf("%v", err)
}

func Errorf(msg string, args ...any) {
	writeMessage(0, "ERROR", msg, args...)
}

func Fatal(err error) {
	Fatalf("%v", err)
}

func Fatalf(msg string, args ...any) {
	text := message("FATAL", msg, args...)
	mu.Lock()
	fl := logFileLogger
	mu.Unlock()
	if fl != nil {
		fl.Print(text)
	}
	golog.Fatal(text)
}

func message(severity, msg string, args ...any) string {
	var sb strings.Builder
	if severity != "" {
		fmt.Fprintf(&sb, "[%s] ", severity)
	}
	if instanceName != "" {
		fmt.Fprintf(&sb, "%s: ", instanceName)
	}
	fmt.Fprintf(&sb, msg, args...)
	return sb.String()
}

func writeMessage(v int, severity, msg string, args ...any) {
	cache := v <= 1 && cachingEnabled.Load()
	if !V(v) && !cache {
		return
	}
	text := message(severity, msg, args...)
	if V(v) {
		golog.Print(text)
		mu.Lock()
		fl := logFileLogger
		mu.Unlock()
		if fl != nil {
			fl.Print(text)
		}
	}
	if !cache {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	cacheMem -= len(cacheEntries[cachePos])
	if cacheMem < 0 {
		panic("log cache size underflow")
	}
	timeStr := ""
	if prependTime {
		timeStr = time.Now().Format("2006/01/02 15:04:05 ")
	}
	cacheEntries[cachePos] = timeStr + text
	cacheMem += len(cacheEntries[cachePos])
	cachePos++
	if cachePos == len(cacheEntries) {
		cachePos = 0
	}
	for i := 0; i < len(cacheEntries)-1 && cacheMem > cacheMaxMem; i++ {
		pos := (cachePos + i) % len(cacheEntries)
		cacheMem -= len(cacheEntries[pos])
		cacheEntries[pos] = ""
	}
	if cacheMem < 0 {
		panic("log cache size underflow")
	}
}

type VerboseWriter int

func (w VerboseWriter) Write(data []byte) (int, error) {
	Logf(int(w), "%s", data)
	return len(data), nil
}
