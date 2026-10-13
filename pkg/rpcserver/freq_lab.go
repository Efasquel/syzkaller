// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
)

// FreqLab brackets every executed test program with a CPU frequency measure.
// For each program it (1) writes the program text to progs/<id>.syz,
// (2) measures the clock, (3) lets the program run, then (4) measures again and
// (5) appends one record -- both measures plus every call's result -- to
// records.jsonl. Each write is fsynced, so a panic loses at most the program
// that caused it, whose text is already on disk.
//
// "Before/after this program" only means something if nothing else runs in
// between, so the runner keeps a single request in flight while FreqLab is on
// (see Runner.maxInFlight). That is the price of attribution: a measure costs
// ~0.18s, so expect a few programs per second instead of hundreds.
//
// Call outputs (IOKit scalar/struct outputs) never reach the manager; the
// executor appends them to outputs.jsonl itself, keyed by the same request id.
type FreqLab struct {
	mu      sync.Mutex
	dir     string
	binfreq string
	args    []string
	records *os.File
	pending map[int64]*freqLabRecord
}

type freqLabRecord struct {
	ID      int64             `json:"id"`
	Prog    string            `json:"prog"`
	Pre     []json.RawMessage `json:"pre,omitempty"`
	PreErr  string            `json:"pre_error,omitempty"`
	Post    []json.RawMessage `json:"post,omitempty"`
	PostErr string            `json:"post_error,omitempty"`
	SentNs  int64             `json:"sent_unix_ns"`
	DoneNs  int64             `json:"done_unix_ns"`
	Status  string            `json:"status"`
	Calls   []freqLabCall     `json:"calls,omitempty"`
}

type freqLabCall struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	Errno    int32  `json:"errno"`
	Executed bool   `json:"executed"`
	Finished bool   `json:"finished"`
	Blocked  bool   `json:"blocked"`
}

// DefaultFreqLabArgs is a fast estimate of both clusters, as JSON: one object
// for P, then one for E (~0.18s together).
var DefaultFreqLabArgs = []string{"-F", "-b", "-j"}

func NewFreqLab(dir, binfreq string, args []string) (*FreqLab, error) {
	if binfreq == "" {
		return nil, fmt.Errorf("freq_lab: binfreq path is required")
	}
	if len(args) == 0 {
		args = DefaultFreqLabArgs
	}
	if err := os.MkdirAll(filepath.Join(dir, "progs"), 0755); err != nil {
		return nil, fmt.Errorf("freq_lab: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "records.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("freq_lab: %w", err)
	}
	return &FreqLab{
		dir:     dir,
		binfreq: binfreq,
		args:    args,
		records: f,
		pending: make(map[int64]*freqLabRecord),
	}, nil
}

// Before saves the program and takes the "pre" measure. It runs on the runner
// goroutine just before the request is sent, so the program cannot have started.
func (fl *FreqLab) Before(id int64, p *prog.Prog) {
	if fl == nil {
		return
	}
	text := p.Serialize()
	name := fmt.Sprintf("%d.syz", id)
	if err := writeFileSync(filepath.Join(fl.dir, "progs", name), text); err != nil {
		fmt.Fprintf(os.Stderr, "freq_lab: saving program %d: %v\n", id, err)
	}
	rec := &freqLabRecord{ID: id, Prog: filepath.Join("progs", name)}
	rec.Pre, rec.PreErr = fl.measure()
	rec.SentNs = time.Now().UnixNano()
	fl.mu.Lock()
	fl.pending[id] = rec
	fl.mu.Unlock()
}

// After takes the "post" measure and appends the record with each call's result.
func (fl *FreqLab) After(id int64, p *prog.Prog, info *flatrpc.ProgInfo, status string) {
	if fl == nil {
		return
	}
	fl.mu.Lock()
	rec := fl.pending[id]
	delete(fl.pending, id)
	fl.mu.Unlock()
	if rec == nil {
		return
	}
	rec.DoneNs = time.Now().UnixNano()
	rec.Status = status
	if info != nil {
		for i, call := range info.Calls {
			c := freqLabCall{
				Index:    i,
				Errno:    call.Error,
				Executed: call.Flags&flatrpc.CallFlagExecuted != 0,
				Finished: call.Flags&flatrpc.CallFlagFinished != 0,
				Blocked:  call.Flags&flatrpc.CallFlagBlocked != 0,
			}
			if i < len(p.Calls) {
				c.Name = p.Calls[i].Meta.Name
			}
			rec.Calls = append(rec.Calls, c)
		}
	}
	rec.Post, rec.PostErr = fl.measure()
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.records.Write(append(line, '\n'))
	fl.records.Sync()
}

func (fl *FreqLab) Close() {
	if fl == nil {
		return
	}
	fl.records.Close()
}

// measure runs binfreq once and returns its JSON objects (one per cluster).
// A failed estimate ("too few uncontended gates") is recorded, not fatal: the
// program still ran, and its call results are still worth keeping.
func (fl *FreqLab) measure() ([]json.RawMessage, string) {
	out, err := exec.Command(fl.binfreq, fl.args...).Output()
	if err != nil {
		msg := err.Error()
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) != 0 {
			msg = string(bytes.TrimSpace(ee.Stderr))
		}
		return nil, msg
	}
	var objs []json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var obj json.RawMessage
		if err := dec.Decode(&obj); err != nil {
			return objs, fmt.Sprintf("parsing binfreq output: %v", err)
		}
		objs = append(objs, obj)
	}
	return objs, ""
}

func writeFileSync(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func freqLabStatus(s queue.Status) string {
	switch s {
	case queue.Success:
		return "success"
	case queue.ExecFailure:
		return "exec_failure"
	case queue.Hanged:
		return "hanged"
	}
	return fmt.Sprint(int(s))
}
