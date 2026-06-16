// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"debug/elf"
	"debug/macho"
	"fmt"
	"io"
	"os"
	"sort"
)

type Symbol struct {
	Addr uint64
	Size int
}

// rawSymbol is a format-neutral symbol used while loading; sizes are absent in
// Mach-O and recomputed from neighbouring symbols by read().
type rawSymbol struct {
	Name  string
	Value uint64
	Size  uint64
}

// ReadTextSymbols returns list of text symbols in the binary bin.
func ReadTextSymbols(bin string) (map[string][]Symbol, error) {
	return read(bin, true)
}

// ReadRodataSymbols returns list of rodata symbols in the binary bin.
func ReadRodataSymbols(bin string) (map[string][]Symbol, error) {
	return read(bin, false)
}

func read(bin string, text bool) (map[string][]Symbol, error) {
	raw, err := load(bin, text)
	if err != nil {
		return nil, err
	}
	sort.Slice(raw, func(i, j int) bool {
		return raw[i].Value > raw[j].Value
	})
	symbols := make(map[string][]Symbol)
	// Function sizes reported by the Linux kernel do not match symbol tables.
	// The kernel computes size of a symbol based on the start of the next symbol.
	// We need to do the same to match kernel sizes to be able to find the right
	// symbol across multiple symbols with the same name.
	var prevAddr uint64
	var prevSize int
	for _, symb := range raw {
		size := int(symb.Size)
		if text {
			if symb.Value == prevAddr {
				size = prevSize
			} else if prevAddr != 0 {
				size = int(prevAddr - symb.Value)
			}
			prevAddr, prevSize = symb.Value, size
		}
		symbols[symb.Name] = append(symbols[symb.Name], Symbol{symb.Value, size})
	}
	return symbols, nil
}

func load(bin string, text bool) ([]rawSymbol, error) {
	if file, err := elf.Open(bin); err == nil {
		defer file.Close()
		return loadELF(file, text)
	}
	// Not an ELF file (e.g. a Mach-O Boot Kernel Collection on Darwin).
	f, err := os.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("failed to open %v: %w", bin, err)
	}
	defer f.Close()
	file, err := macho.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to open %v as an ELF or Mach-O file: %w", bin, err)
	}
	defer file.Close()
	// A Mach-O kernel collection (MH_FILESET) has no top-level symbol table;
	// each kernel/kext lives in a nested Mach-O referenced by LC_FILESET_ENTRY.
	if file.Symtab == nil {
		return loadMachOFileSet(f, file, text)
	}
	return loadMachO(file, text)
}

func loadELF(file *elf.File, text bool) ([]rawSymbol, error) {
	allSymbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read ELF symbols: %w", err)
	}
	var symbols []rawSymbol
	for _, symb := range allSymbols {
		if symb.Size == 0 || symb.Section < 0 || int(symb.Section) >= len(file.Sections) {
			continue
		}
		sect := file.Sections[symb.Section]
		isText := sect.Type == elf.SHT_PROGBITS &&
			sect.Flags&elf.SHF_ALLOC != 0 &&
			sect.Flags&elf.SHF_EXECINSTR != 0
		// Note: x86_64 vmlinux .rodata is marked as writable and according to flags it looks like .data,
		// so we look at the name.
		if text && !isText || !text && sect.Name != ".rodata" {
			continue
		}
		symbols = append(symbols, rawSymbol{Name: symb.Name, Value: symb.Value, Size: symb.Size})
	}
	return symbols, nil
}

func loadMachO(file *macho.File, text bool) ([]rawSymbol, error) {
	if file.Symtab == nil {
		return nil, fmt.Errorf("failed to read Mach-O symbols")
	}
	// Mach-O symbols carry no size; read() recomputes text sizes from the next
	// symbol, so we only need to keep those landing in the requested section.
	sectName := "__text"
	if !text {
		sectName = "__const"
	}
	var symbols []rawSymbol
	for _, symb := range file.Symtab.Syms {
		// Sect is a 1-based section index; 0 means the symbol has no section.
		if symb.Sect == 0 || int(symb.Sect) > len(file.Sections) {
			continue
		}
		if file.Sections[symb.Sect-1].Name != sectName {
			continue
		}
		symbols = append(symbols, rawSymbol{Name: symb.Name, Value: symb.Value})
	}
	return symbols, nil
}

// Mach-O load command and structure constants needed to walk an MH_FILESET.
const (
	lcSegment64    = 0x19
	lcSymtab       = 0x2
	lcFilesetEntry = 0x80000035 // LC_FILESET_ENTRY (0x35 | LC_REQ_DYLD)

	machHeader64Size = 32
	segment64HdrSize = 72 // up to and including nsects/flags
	section64Size    = 80
	nlist64Size      = 16
)

// NamedSym is a symbol name/value pair from a Mach-O fileset entry.
type NamedSym struct {
	Name  string
	Value uint64
}

// MachoEntry describes one nested Mach-O (kernel or kext) of an MH_FILESET kernel
// collection: its entry id, its __text section span (TextOff is the file offset of
// __text, file-absolute in a fileset) and the text symbols it owns.
type MachoEntry struct {
	Name     string
	TextAddr uint64
	TextEnd  uint64
	TextOff  uint64
	Symbols  []NamedSym
}

// ReadMachoFileSetEntries returns the nested entries of a Mach-O kernel collection
// (MH_FILESET), each with its __text range and text symbols. Used by the coverage
// backend to synthesize per-kext compile units without DWARF.
func ReadMachoFileSetEntries(bin string) ([]MachoEntry, error) {
	f, err := os.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("failed to open %v: %w", bin, err)
	}
	defer f.Close()
	file, err := macho.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to open %v as a Mach-O file: %w", bin, err)
	}
	defer file.Close()
	var entries []MachoEntry
	err = eachFileSetEntry(f, file, func(name string, info *entryInfo) {
		e := MachoEntry{Name: name}
		// An entry may carry several sections named __text (e.g. an empty
		// __TEXT,__text plus the real __TEXT_EXEC,__text on the kernel); pick the
		// largest so the range covers the executable code.
		var bestSize uint64
		for i := range info.sections {
			s := &info.sections[i]
			if s.name == "__text" && s.size > bestSize {
				e.TextAddr = s.addr
				e.TextEnd = s.addr + s.size
				e.TextOff = s.off
				bestSize = s.size
			}
		}
		for _, sym := range info.syms {
			if sym.sect == 0 || int(sym.sect) > len(info.sections) {
				continue
			}
			if info.sections[sym.sect-1].name != "__text" {
				continue
			}
			e.Symbols = append(e.Symbols, NamedSym{Name: sym.name, Value: sym.value})
		}
		entries = append(entries, e)
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// loadMachOFileSet reads symbols from a Mach-O kernel collection (MH_FILESET).
// Such files have no top-level symbol table; instead every kernel/kext is a
// nested Mach-O addressed by an LC_FILESET_ENTRY. The nested entries' symbol and
// string table offsets are absolute (relative to the whole file), so we parse
// each entry's load commands at its fileoff but read the tables from r directly.
func loadMachOFileSet(r io.ReaderAt, file *macho.File, text bool) ([]rawSymbol, error) {
	sectName := "__text"
	if !text {
		sectName = "__const"
	}
	var symbols []rawSymbol
	err := eachFileSetEntry(r, file, func(_ string, info *entryInfo) {
		for _, sym := range info.syms {
			if sym.sect == 0 || int(sym.sect) > len(info.sections) {
				continue
			}
			if info.sections[sym.sect-1].name != sectName {
				continue
			}
			symbols = append(symbols, rawSymbol{Name: sym.name, Value: sym.value})
		}
	})
	if err != nil {
		return nil, err
	}
	if len(symbols) == 0 {
		return nil, fmt.Errorf("no symbols found in Mach-O fileset")
	}
	return symbols, nil
}

// machoSection / entrySym / entryInfo hold the parsed innards of a nested Mach-O.
type machoSection struct {
	name string
	addr uint64
	size uint64
	off  uint64 // file offset of the section data (file-absolute in a fileset)
}

type entrySym struct {
	name  string
	value uint64
	sect  uint8 // n_sect, 1-based index into entryInfo.sections
}

type entryInfo struct {
	sections []machoSection
	syms     []entrySym
}

// eachFileSetEntry walks every LC_FILESET_ENTRY of an MH_FILESET, parses the nested
// Mach-O it points at and invokes fn with the entry id and its parsed contents.
// Entries that fail to parse are skipped rather than failing the whole walk.
func eachFileSetEntry(r io.ReaderAt, file *macho.File, fn func(name string, info *entryInfo)) error {
	bo := file.ByteOrder
	n := 0
	for _, l := range file.Loads {
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		raw := lb.Raw()
		if len(raw) < 28 || bo.Uint32(raw[0:4]) != lcFilesetEntry {
			continue
		}
		fileoff := bo.Uint64(raw[16:24])
		nameOff := bo.Uint32(raw[24:28]) // entry_id, an lc_str offset within the command
		name := ""
		if int(nameOff) < len(raw) {
			name = cstr(raw[nameOff:])
		}
		info, err := parseMachoEntry(r, bo, int64(fileoff))
		if err != nil {
			continue
		}
		fn(name, info)
		n++
	}
	if n == 0 {
		return fmt.Errorf("no entries in Mach-O fileset")
	}
	return nil
}

// parseMachoEntry parses the nested Mach-O header at headerOff, returning its
// sections (in 1-based n_sect order) and symbols. Symbol/string table offsets in
// the entry's LC_SYMTAB are absolute (relative to the whole file), so we read them
// from r directly.
func parseMachoEntry(r io.ReaderAt, bo byteOrder, headerOff int64) (*entryInfo, error) {
	hdr := make([]byte, machHeader64Size)
	if _, err := r.ReadAt(hdr, headerOff); err != nil {
		return nil, err
	}
	ncmds := bo.Uint32(hdr[16:20])
	sizeofcmds := bo.Uint32(hdr[20:24])
	cmds := make([]byte, sizeofcmds)
	if _, err := r.ReadAt(cmds, headerOff+machHeader64Size); err != nil {
		return nil, err
	}

	info := &entryInfo{}
	var symoff, nsyms, stroff, strsize uint32
	for i, off := uint32(0), uint32(0); i < ncmds && off+8 <= sizeofcmds; i++ {
		cmd := bo.Uint32(cmds[off : off+4])
		csz := bo.Uint32(cmds[off+4 : off+8])
		if csz < 8 || off+csz > sizeofcmds {
			break
		}
		switch cmd {
		case lcSegment64:
			nsects := bo.Uint32(cmds[off+64 : off+68])
			for j := uint32(0); j < nsects; j++ {
				so := off + segment64HdrSize + j*section64Size
				if so+section64Size > sizeofcmds {
					break
				}
				info.sections = append(info.sections, machoSection{
					name: cstr(cmds[so : so+16]),
					addr: bo.Uint64(cmds[so+32 : so+40]),
					size: bo.Uint64(cmds[so+40 : so+48]),
					off:  uint64(bo.Uint32(cmds[so+48 : so+52])),
				})
			}
		case lcSymtab:
			symoff = bo.Uint32(cmds[off+8 : off+12])
			nsyms = bo.Uint32(cmds[off+12 : off+16])
			stroff = bo.Uint32(cmds[off+16 : off+20])
			strsize = bo.Uint32(cmds[off+20 : off+24])
		}
		off += csz
	}
	if nsyms == 0 {
		return info, nil
	}
	syms := make([]byte, int(nsyms)*nlist64Size)
	if _, err := r.ReadAt(syms, int64(symoff)); err != nil {
		return nil, err
	}
	strs := make([]byte, strsize)
	if _, err := r.ReadAt(strs, int64(stroff)); err != nil {
		return nil, err
	}
	for s := uint32(0); s < nsyms; s++ {
		b := syms[s*nlist64Size : s*nlist64Size+nlist64Size]
		strx := bo.Uint32(b[0:4])
		if int(strx) >= len(strs) {
			continue
		}
		info.syms = append(info.syms, entrySym{
			name:  cstr(strs[strx:]),
			value: bo.Uint64(b[8:16]),
			sect:  b[5], // n_sect, 1-based
		})
	}
	return info, nil
}

// byteOrder is the subset of binary.ByteOrder used here (macho.File.ByteOrder).
type byteOrder interface {
	Uint32([]byte) uint32
	Uint64([]byte) uint64
}

func cstr(b []byte) string {
	if i := indexZero(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
