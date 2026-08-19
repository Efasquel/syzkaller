package flatrpc

import (
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
)

func TestConnectReplyCoverStepsRoundTrip(t *testing.T) {
	orig := &ConnectReplyRawT{
		Debug:            true,
		Cover:            true,
		Procs:            7,
		Slowdown:         3,
		SyscallTimeoutMs: 111,
		ProgramTimeoutMs: 222,
		LeakFrames:       []string{"lf1", "lf2"},
		Files:            []string{"/a", "/b"},
		KcovDevice:       "/dev/pishi",
		KextId:           9,
		CoverStepsFile:   "/tmp/steps.log",
	}
	b := flatbuffers.NewBuilder(0)
	b.Finish(orig.Pack(b))
	got := GetRootAsConnectReplyRaw(b.FinishedBytes(), 0).UnPack()

	if got.CoverStepsFile != orig.CoverStepsFile {
		t.Fatalf("CoverStepsFile = %q, want %q", got.CoverStepsFile, orig.CoverStepsFile)
	}
	// Prove appending the field did not disturb neighbors / vtable.
	if got.KextId != orig.KextId || got.KcovDevice != orig.KcovDevice ||
		got.Procs != orig.Procs || got.ProgramTimeoutMs != orig.ProgramTimeoutMs ||
		!got.Debug || !got.Cover || len(got.Files) != 2 || got.Files[1] != "/b" {
		t.Fatalf("neighbor fields corrupted: %+v", got)
	}
	// Empty CoverStepsFile must round-trip to empty (default, not written).
	empty := (&ConnectReplyRawT{KextId: 5}).Pack(flatbuffers.NewBuilder(0))
	_ = empty
}
