// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func freqLabTestProg(t *testing.T) *prog.Prog {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("test()\ntest()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func stubBinfreq(t *testing.T, body string) string {
	path := filepath.Join(t.TempDir(), "binfreq")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFreqLabRecords(t *testing.T, dir string) []freqLabRecord {
	data, err := os.ReadFile(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var recs []freqLabRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec freqLabRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad record %q: %v", line, err)
		}
		recs = append(recs, rec)
	}
	return recs
}

func TestFreqLabRecordsBothMeasuresAndCallResults(t *testing.T) {
	dir := t.TempDir()
	// Two concatenated objects, as binfreq -b -j prints one per cluster.
	bin := stubBinfreq(t, `echo '{"ghz": 3.5, "cluster": "P"}'; echo '{"ghz": 2.4, "cluster": "E"}'`)
	fl, err := NewFreqLab(dir, bin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fl.Close()
	p := freqLabTestProg(t)

	fl.Before(7, p)
	if _, err := os.Stat(filepath.Join(dir, "progs", "7.syz")); err != nil {
		t.Fatalf("program not saved before execution: %v", err)
	}
	info := &flatrpc.ProgInfo{Calls: []*flatrpc.CallInfo{
		{Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, Error: 0},
		{Flags: flatrpc.CallFlagExecuted, Error: 1},
	}}
	fl.After(7, p, info, "success")

	recs := readFreqLabRecords(t, dir)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	rec := recs[0]
	if rec.ID != 7 || rec.Prog != "progs/7.syz" || rec.Status != "success" {
		t.Errorf("bad record header: %+v", rec)
	}
	if len(rec.Pre) != 2 || len(rec.Post) != 2 {
		t.Errorf("want P and E on both sides, got pre=%d post=%d", len(rec.Pre), len(rec.Post))
	}
	if len(rec.Calls) != 2 || !rec.Calls[0].Finished || rec.Calls[1].Errno != 1 || rec.Calls[0].Name != "test" {
		t.Errorf("bad call results: %+v", rec.Calls)
	}
	if rec.DoneNs < rec.SentNs {
		t.Errorf("done before sent: %+v", rec)
	}
}

func TestFreqLabKeepsTheRecordWhenAMeasureFails(t *testing.T) {
	// binfreq gives up on noisy machines; the program still ran, so its call
	// results must still be recorded, with the failure noted.
	dir := t.TempDir()
	bin := stubBinfreq(t, `echo 'binfreq: too few uncontended gates to estimate' >&2; exit 1`)
	fl, err := NewFreqLab(dir, bin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fl.Close()
	p := freqLabTestProg(t)
	fl.Before(1, p)
	fl.After(1, p, &flatrpc.ProgInfo{Calls: []*flatrpc.CallInfo{{}, {}}}, "success")
	rec := readFreqLabRecords(t, dir)[0]
	if !strings.Contains(rec.PreErr, "uncontended") || !strings.Contains(rec.PostErr, "uncontended") {
		t.Errorf("measure failure not recorded: %+v", rec)
	}
	if len(rec.Calls) != 2 {
		t.Errorf("call results lost: %+v", rec)
	}
}

func TestNilFreqLabIsANoOp(t *testing.T) {
	var fl *FreqLab
	fl.Before(1, nil)
	fl.After(1, nil, nil, "")
	fl.Close()
}
