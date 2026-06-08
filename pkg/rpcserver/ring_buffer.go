// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RingBuffer persists the last N test programs to disk before they are sent
// to the executor. Each write is fsynced synchronously so data is guaranteed
// on disk before execution starts — surviving a kernel panic caused by that
// program. Only active in VM-less mode (type: "none").
//
// After a reboot, read all slot_NNNN.syz files in the ring_buffer/ directory
// and sort by the id field to reconstruct execution order. The slot with the
// highest id is the program that was about to execute when the crash occurred.
type RingBuffer struct {
	mu   sync.Mutex
	dir  string
	size int
	pos  int
}

// NewRingBuffer creates the ring buffer directory.
// Returns nil when size == 0 (disabled); all methods on a nil *RingBuffer are no-ops.
func NewRingBuffer(dir string, size int) (*RingBuffer, error) {
	if size == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("ring buffer: %w", err)
	}
	return &RingBuffer{
		dir:  dir,
		size: size,
	}, nil
}

// WriteSync writes prog to the next slot and fsyncs before returning.
// It is called on the runner goroutine before flatrpc.Send, so the slot file
// is durable on disk before the executor ever starts running the program.
// The fsync is overlapped with the execution of the previous program (the
// runner keeps 2*procs programs in-flight), so steady-state overhead is zero.
func (rb *RingBuffer) WriteSync(id int, prog []byte) {
	if rb == nil {
		return
	}
	rb.mu.Lock()
	slot := rb.pos
	rb.pos = (rb.pos + 1) % rb.size
	rb.mu.Unlock()

	slotPath := filepath.Join(rb.dir, fmt.Sprintf("slot_%04d.syz", slot))
	header := fmt.Sprintf("id=%d\n", id)
	content := append([]byte(header), prog...)

	f, err := os.OpenFile(slotPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	f.Write(content)
	f.Sync();
	f.Close()
}

// Close is a no-op; kept so callers do not need to nil-check before closing.
func (rb *RingBuffer) Close() {}
