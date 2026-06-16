// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
)

// DarwinKaslrAnchor is the symbol used to recover the kernel slide on Darwin.
// It must match the symbol whose runtime address the Pishi kext returns via
// PISHI_IOCTL_KASLR (see executor/executor_darwin.h). On the Pishi BKC this same
// symbol is the SanitizerCoverage callback that instrumented code BL-calls at the
// start of every basic block, so it doubles as the cover-point anchor.
const DarwinKaslrAnchor = "_sanitizer_cov_trace_pc"

// machoReadTextSecRange returns the address range of the __text section, the
// Mach-O equivalent of elfReadTextSecRange (used by DiscoverModules).
func machoReadTextSecRange(module *vminfo.KernelModule) (*SecRange, error) {
	file, err := macho.Open(module.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	text := file.Section("__text")
	if text == nil {
		return nil, fmt.Errorf("no __text section in %v", module.Path)
	}
	return &SecRange{
		Start: text.Addr,
		End:   text.Addr + text.Size,
	}, nil
}

// MachoStaticSymbolAddr returns the static (unslid) value of the named text
// symbol from a Mach-O file. Used to recover the Darwin kernel slide:
// slide = runtime_addr(symbol) - MachoStaticSymbolAddr(bkc, symbol).
// ReadTextSymbols handles MH_FILESET kernel collections, where symbols live in
// nested entries (e.g. the anchor symbol lives in the Pishi kext, not the kernel).
func MachoStaticSymbolAddr(path, name string) (uint64, error) {
	symbols, err := symbolizer.ReadTextSymbols(path)
	if err != nil {
		return 0, err
	}
	syms := symbols[name]
	if len(syms) == 0 {
		return 0, fmt.Errorf("symbol %q not found in %v", name, path)
	}
	return syms[0].Addr, nil
}

// makeMachO builds the coverage Impl for the Darwin kernel image, which is a
// Boot Kernel Collection (MH_FILESET). There is no DWARF for the fuzzed kexts, so
// instead of going through makeDWARF we synthesize the structures the report
// generator needs directly from the symbol table and the SanitizerCoverage call
// sites: one CompileUnit per fileset entry (kext), function symbols from each
// entry's symtab, and basic-block cover points found by scanning __text for BL
// calls to the cover callback. Frames are synthesized in machoSymbolize.
func makeMachO(target *targets.Target, kernelDirs *mgrconfig.KernelDirs,
	moduleObj []string, hostModules []*vminfo.KernelModule) (*Impl, error) {
	var kernel *vminfo.KernelModule
	for _, m := range hostModules {
		if m.Name == "" {
			kernel = m
			break
		}
	}
	if kernel == nil {
		return nil, fmt.Errorf("no kernel module for Darwin coverage")
	}
	entries, err := symbolizer.ReadMachoFileSetEntries(kernel.Path)
	if err != nil {
		return nil, err
	}
	// Coverage PCs are STATIC (un-slid) here, so we build symbols at their BKC
	// link-time addresses. Pishi's trampolines load the original PC into x1 from
	// MOVZ/MOVK immediates baked into the BKC and pass it to _sanitizer_cov_trace_pc
	// (which records x1, not its return address). KASLR slides where code executes
	// but not those immediates, so kcov reports link-time addresses. The
	// canonicalizer also passes the kernel module (Name=="") through unchanged.
	// (The KASLR slide is still needed elsewhere, for symbolizing runtime crash PCs.)

	// Pishi instruments by replacing each basic block's first instruction with an
	// unconditional B into a trampoline in the Pishi entry; the trampoline records
	// the original PC (the B instruction's own address) via _sanitizer_cov_trace_pc
	// and branches back. So the Pishi entry is the thunk region, and a basic block
	// is any B whose target lands inside it. Identify the Pishi entry by the anchor.
	var pishiStart, pishiEnd uint64
	for i := range entries {
		for _, s := range entries[i].Symbols {
			if s.Name == DarwinKaslrAnchor {
				pishiStart, pishiEnd = entries[i].TextAddr, entries[i].TextEnd
			}
		}
	}
	if pishiStart == 0 {
		return nil, fmt.Errorf("cover callback %q not found in %v", DarwinKaslrAnchor, kernel.Path)
	}

	f, err := os.Open(kernel.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var allSymbols []*Symbol
	var allRanges []pcRange
	var allUnits []*CompileUnit
	var allCoverPoints [2][]uint64
	for i := range entries {
		e := &entries[i]
		if e.TextEnd <= e.TextAddr || len(e.Symbols) == 0 {
			continue
		}
		unit := &CompileUnit{
			ObjectUnit: ObjectUnit{Name: e.Name},
			Path:       e.Name,
			Module:     kernel,
		}
		allUnits = append(allUnits, unit)
		allRanges = append(allRanges, pcRange{e.TextAddr, e.TextEnd, unit})

		// Mach-O symbols carry no size; estimate each symbol's end from the next
		// symbol (sorted), clamped to the entry's __text end.
		syms := append([]symbolizer.NamedSym(nil), e.Symbols...)
		sort.Slice(syms, func(a, b int) bool { return syms[a].Value < syms[b].Value })
		for j := range syms {
			s := syms[j]
			if s.Value < e.TextAddr || s.Value >= e.TextEnd {
				continue
			}
			end := e.TextEnd
			if j < len(syms)-1 && syms[j+1].Value > s.Value && syms[j+1].Value <= e.TextEnd {
				end = syms[j+1].Value
			}
			allSymbols = append(allSymbols, &Symbol{
				Module:     kernel,
				ObjectUnit: ObjectUnit{Name: s.Name},
				Start:      s.Value,
				End:        end,
			})
		}

		// The Pishi entry is the trampoline pool itself, not instrumented code.
		if e.TextAddr == pishiStart {
			continue
		}
		// Enumerate basic blocks: each B into the Pishi thunk region marks a block
		// whose PC is the B instruction's address. Section offsets are file-absolute.
		data := make([]byte, e.TextEnd-e.TextAddr)
		if _, err := f.ReadAt(data, int64(e.TextOff)); err != nil {
			return nil, fmt.Errorf("failed to read __text of %v: %w", e.Name, err)
		}
		for off := 0; off+4 <= len(data); off += 4 {
			insn := binary.LittleEndian.Uint32(data[off : off+4])
			if insn&0xfc000000 != 0x14000000 { // B (unconditional immediate branch)
				continue
			}
			pc := e.TextAddr + uint64(off)
			tgt := branchTarget(insn, pc)
			if tgt >= pishiStart && tgt < pishiEnd {
				allCoverPoints[0] = append(allCoverPoints[0], pc)
			}
		}
	}

	// Deduplicate symbols sharing a start address (aliases), then sort everything
	// so buildSymbols can assign cover points and units in a single pass.
	uniq := make(map[uint64]*Symbol)
	for _, s := range allSymbols {
		if _, ok := uniq[s.Start]; !ok {
			uniq[s.Start] = s
		}
	}
	allSymbols = allSymbols[:0]
	for _, s := range uniq {
		allSymbols = append(allSymbols, s)
	}
	sort.Slice(allSymbols, func(i, j int) bool { return allSymbols[i].Start < allSymbols[j].Start })
	sort.Slice(allRanges, func(i, j int) bool { return allRanges[i].start < allRanges[j].start })
	for k := range allCoverPoints {
		sort.Slice(allCoverPoints[k], func(i, j int) bool { return allCoverPoints[k][i] < allCoverPoints[k][j] })
	}

	allSymbols = buildSymbols(allSymbols, allRanges, allCoverPoints)
	nunit := 0
	for _, unit := range allUnits {
		if len(unit.PCs) == 0 {
			continue // drop entries with no cover points (uninstrumented)
		}
		allUnits[nunit] = unit
		nunit++
	}
	allUnits = allUnits[:nunit]
	if len(allSymbols) == 0 || len(allUnits) == 0 {
		return nil, fmt.Errorf("no coverage symbols found in %v (is the kernel instrumented?)", kernel.Path)
	}

	// symByStart is a sorted snapshot used to map a PC back to its function.
	symByStart := append([]*Symbol(nil), allSymbols...)
	sort.Slice(symByStart, func(i, j int) bool { return symByStart[i].Start < symByStart[j].Start })

	impl := &Impl{
		Units:   allUnits,
		Symbols: allSymbols,
		Symbolize: func(pcs map[*vminfo.KernelModule][]uint64) ([]*Frame, error) {
			return machoSymbolize(symByStart, pcs), nil
		},
		CallbackPoints: allCoverPoints[0],
		// No DWARF: we cannot verify kcov PCs against exact callback locations.
		PreciseCoverage: false,
	}
	return impl, nil
}

// branchTarget returns the destination of an arm64 B/BL (imm26) instruction at pc.
func branchTarget(insn uint32, pc uint64) uint64 {
	off := uint64(insn & 0x3ffffff)
	if off>>25 == 1 {
		off |= 0xfffffffffc000000 // sign-extend the 26-bit offset
	}
	return pc + 4*off
}

// machoSymbolize maps each PC to the function symbol that contains it, producing a
// Frame whose "file" is the owning kext (Unit) and whose "function" is the symbol.
// Without DWARF there are no real source lines, so every frame collapses to a
// single synthetic line (Phase 2 will itemize basic blocks).
func machoSymbolize(symByStart []*Symbol, pcs map[*vminfo.KernelModule][]uint64) []*Frame {
	var frames []*Frame
	for _, list := range pcs {
		for _, pc := range list {
			// Rightmost symbol with Start <= pc.
			idx := sort.Search(len(symByStart), func(i int) bool { return symByStart[i].Start > pc }) - 1
			if idx < 0 {
				continue
			}
			s := symByStart[idx]
			if pc >= s.End || s.Unit == nil {
				continue
			}
			frames = append(frames, &Frame{
				Module:   s.Module,
				PC:       pc,
				Name:     s.Unit.Name,
				FuncName: s.Name,
				Path:     s.Unit.Path,
				Range: Range{
					StartLine: 1,
					StartCol:  0,
					EndLine:   1,
					EndCol:    LineEnd,
				},
			})
		}
	}
	return frames
}
