// elf.go implements GNU file(1)-compatible reporting for ELF binaries.
//
// GNU file describes an ELF image in two halves:
//
//	ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, ...
//	`------------ header fields -------------'  `------ whole-file fields ------'
//
// The header half comes from the first 64 bytes (class, byte order, object
// type, machine, ELF version, OS/ABI). The rest requires walking the program
// headers, the section headers and the note records, which are scattered
// through the whole file.
//
// [elfDetail] therefore has two paths:
//
//   - [elfAnalyse] opens the file with debug/elf and produces the full GNU
//     description. It needs a seekable path.
//   - [elfHeaderOnly] uses just the magic-byte window and stops after the
//     OS/ABI. It is the fallback for stdin, pipes and anything debug/elf
//     refuses to parse.
//
// The layout of the description follows file(1) closely enough that the two
// can be diffed line by line; see the "GNU file compatibility" section of
// README.md for the deliberate differences.
package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// GNU file reads program-header payloads (PT_INTERP, PT_DYNAMIC, PT_NOTE)
// into a stack buffer of BUFSIZ bytes and silently ignores the remainder.
// BUFSIZ is 8192 on glibc; matching it matters for core dumps, whose note
// segment is routinely larger than that.
const elfSegReadMax = 8192

// Caps taken from file.h: FILE_ELF_NOTES_MAX, and the auxv guard in
// do_auxv_note().
const (
	elfNotesMax = 256
	elfAuxvMax  = 50
)

// Note types and note-name conventions, from file's readelf.h.
const (
	ntGNUABITag    = 1 // NT_GNU_VERSION in file's headers
	ntGNUBuildID   = 3
	ntGoBuildID    = 4
	ntPrpsinfo     = 3
	ntAuxv         = 6
	ntNetBSDPax    = 3
	ntNetBSDVer    = 1
	ntNetBSDMarch  = 5
	ntNetBSDCmodel = 6
	ntNetBSDEmul   = 7
	ntFreeBSDVer   = 1
	ntOpenBSDVer   = 1
	ntDragonFlyVer = 1
)

// Auxiliary-vector tags file(1) reports for SVR4-style core dumps.
const (
	atUID      = 11
	atEUID     = 12
	atGID      = 13
	atEGID     = 14
	atPlatform = 15
	atExecfn   = 31
)

const (
	dtNeeded = 1
	dtFlags1 = 0x6ffffffb
	df1PIE   = 0x08000000
)

// Core-dump note flavours, in the order of file's os_style_names[].
const (
	coreStyleSVR4 = iota
	coreStyleFreeBSD
	coreStyleNetBSD
)

var coreStyleNames = [...]string{"SVR4", "FreeBSD", "NetBSD"}

// elfOSABI is the EI_OSABI table from magic/Magdir/elf. Values outside it
// produce no "(...)" suffix at all, which is what GNU file does.
var elfOSABI = map[byte]string{
	0:   "(SYSV)",
	1:   "(HP-UX)",
	2:   "(NetBSD)",
	3:   "(GNU/Linux)",
	4:   "(GNU/Hurd)",
	5:   "(86Open)",
	6:   "(Solaris)",
	7:   "(Monterey)",
	8:   "(IRIX)",
	9:   "(FreeBSD)",
	10:  "(Tru64)",
	11:  "(Novell Modesto)",
	12:  "(OpenBSD)",
	13:  "(OpenVMS)",
	14:  "(HP NonStop Kernel)",
	15:  "(AROS Research Operating System)",
	16:  "(FenixOS)",
	17:  "(Nuxi CloudABI)",
	97:  "(ARM)",
	202: "(Cafe OS)",
	255: "(embedded)",
}

// prpsoffsets are the byte offsets within an NT_PRPSINFO note at which the
// process name has been observed to live, largest first so that a shorter
// candidate cannot match inside a longer string. Straight from readelf.c.
var (
	prpsoffsets32 = []int{100, 84, 44, 28, 48, 32, 8}
	prpsoffsets64 = []int{136, 120, 56, 40, 16}
)

// elfHdr is the fixed ELF header, read straight out of the magic-byte window
// at the byte offsets GNU file's magic entries use.
//
// Each field carries a "was it there" flag because file(1) reports exactly the
// fields the available bytes cover: a 5-byte fragment yields "ELF 64-bit", an
// 18-byte one adds the object type but neither the machine nor the version.
type elfHdr struct {
	class   byte // EI_CLASS: 1 = 32-bit, 2 = 64-bit
	data    byte // EI_DATA: 1 = LSB, 2 = MSB
	osabi   byte
	bo      binary.ByteOrder
	etype   uint16
	machine uint16
	version uint32 // e_version, not EI_VERSION
	flags   uint32 // e_flags, at the offset for this class
	flags64 uint32 // e_flags read at offset 48 regardless of class (see elfMachineText)
	shnum   uint16

	hasClass   bool
	hasData    bool
	hasOSABI   bool
	hasType    bool
	hasMachine bool
	hasVersion bool

	fields bool // EI_DATA was 1 or 2, so the type/machine/version fields apply
}

func parseELFHdr(buf []byte) elfHdr {
	h := elfHdr{bo: binary.LittleEndian}
	if len(buf) >= 5 {
		h.class, h.hasClass = buf[4], true
	}
	if len(buf) >= 6 {
		h.data, h.hasData = buf[5], true
	}
	if len(buf) >= 8 {
		h.osabi, h.hasOSABI = buf[7], true
	}
	// file(1) compares the host byte order against EI_DATA, so anything
	// other than ELFDATA2LSB is treated as big-endian.
	if h.data != 1 {
		h.bo = binary.BigEndian
	}
	h.fields = h.data == 1 || h.data == 2
	if len(buf) >= 18 {
		h.etype, h.hasType = h.bo.Uint16(buf[16:]), true
	}
	if len(buf) >= 20 {
		h.machine, h.hasMachine = h.bo.Uint16(buf[18:]), true
	}
	if len(buf) >= 24 {
		h.version, h.hasVersion = h.bo.Uint32(buf[20:]), true
	}
	switch h.class {
	case 1:
		if len(buf) >= 50 {
			h.flags = h.bo.Uint32(buf[36:])
			h.shnum = h.bo.Uint16(buf[48:])
		}
	case 2:
		if len(buf) >= 62 {
			h.flags = h.bo.Uint32(buf[48:])
			h.shnum = h.bo.Uint16(buf[60:])
		}
	}
	if len(buf) >= 52 {
		h.flags64 = h.bo.Uint32(buf[48:])
	}
	return h
}

// elfDetail is the entry point from detectMagic. path is empty when the bytes
// did not come from a seekable file (stdin, or a payload unwrapped from a
// compressed outer file), in which case only the header fields are reported.
func elfDetail(buf []byte, path string) *magicResult {
	if path != "" {
		if mr := elfAnalyse(buf, path); mr != nil {
			return mr
		}
	}
	return elfHeaderOnly(buf)
}

func elfResult(h elfHdr, pie bool, detail string) *magicResult {
	return &magicResult{
		desc: elfPrefix(h, pie) + detail,
		mime: elfMIME(h, pie),
		ext:  "elf",
	}
}

// elfHeaderOnly describes an ELF image from the magic-byte window alone.
func elfHeaderOnly(buf []byte) *magicResult {
	h := parseELFHdr(buf)
	// Without the program headers there is no way to tell a PIE executable
	// from a shared library, so report the conservative "shared object".
	return elfResult(h, false, "")
}

// elfMIME maps the object type to the MIME type GNU file reports. Types with
// no mapping of their own fall back to the generic binary type, which is what
// file(1) ends up printing for them.
func elfMIME(h elfHdr, pie bool) string {
	mime := "application/octet-stream"
	if !h.fields || !h.hasType {
		return mime
	}
	switch h.etype {
	case 1:
		mime = "application/x-object"
	case 2:
		mime = "application/x-executable"
	case 3:
		if pie {
			mime = "application/x-pie-executable"
		} else {
			mime = "application/x-sharedlib"
		}
	case 4:
		mime = "application/x-coredump"
	}
	// The two OS- and processor-specific overrides, in magic-file order.
	if h.osabi == 202 && h.etype == 0xFE01 {
		mime = "application/x-executable"
	}
	if h.etype&0xff00 != 0 && h.machine == 8 && h.etype == 0xFF80 {
		mime = "application/x-sharedlib"
	}
	return mime
}

// elfPrefix renders the part of the description that comes from the ELF
// header. GNU file builds it by appending " " + text for each magic line that
// matches, which is why the type and machine strings carry their own trailing
// commas and an unknown OS/ABI contributes nothing.
func elfPrefix(h elfHdr, pie bool) string {
	var b strings.Builder
	b.WriteString("ELF")
	if h.hasClass {
		switch h.class {
		case 0:
			b.WriteString(" invalid class")
		case 1:
			b.WriteString(" 32-bit")
		case 2:
			b.WriteString(" 64-bit")
		}
	}
	if h.hasData {
		switch h.data {
		case 0:
			b.WriteString(" invalid byte order")
		case 1:
			b.WriteString(" LSB")
		case 2:
			b.WriteString(" MSB")
		}
	}
	if h.fields {
		if h.hasType {
			for _, s := range elfTypeText(h, pie) {
				b.WriteString(" " + s)
			}
		}
		if h.hasMachine {
			if s := elfMachineText(h); s != "" {
				b.WriteString(" " + s)
			}
		}
		if h.hasVersion {
			switch h.version {
			case 0:
				b.WriteString(" invalid version")
			case 1:
				b.WriteString(" version 1")
			}
		}
	}
	if h.hasOSABI {
		if s, ok := elfOSABI[h.osabi]; ok {
			b.WriteString(" " + s)
		}
	}
	return b.String()
}

// elfTypeText returns the e_type descriptions, which can be more than one:
// the OS-specific and processor-specific magic lines are additive.
func elfTypeText(h elfHdr, pie bool) []string {
	var out []string
	switch h.etype {
	case 0:
		out = append(out, "no file type,")
	case 1:
		out = append(out, "relocatable,")
	case 2:
		out = append(out, "executable,")
	case 3:
		// Not an ELF field: file(1) calls an ET_DYN image a PIE executable
		// when its .dynamic section carries DT_FLAGS_1 with DF_1_PIE, and a
		// shared library otherwise.
		if pie {
			out = append(out, "pie executable,")
		} else {
			out = append(out, "shared object,")
		}
	case 4:
		out = append(out, "core file,")
	}
	if h.osabi == 202 && h.etype == 0xFE01 {
		out = append(out, "executable,")
	}
	if h.etype&0xff00 != 0 {
		if h.machine == 8 && h.etype == 0xFF80 {
			out = append(out, "PlayStation 2 IOP module,")
		} else {
			out = append(out, "processor-specific,")
		}
	}
	return out
}

// elfMachineText names the e_machine values winfile covers, with the
// flag-derived ABI suffixes GNU file appends for them. The full e_machine
// table has well over a hundred entries; anything outside this set is left
// unnamed rather than guessed at, so those files get the broad description.
func elfMachineText(h elfHdr) string {
	switch h.machine {
	case 3:
		return "Intel 80386,"
	case 21:
		// magic/Magdir/elf reads the Power ABI level at offset 48
		// unconditionally, i.e. from the 64-bit e_flags slot.
		s := "64-bit PowerPC or cisco 7500,"
		switch h.flags64 {
		case 0:
			s += " Unspecified or Power ELF V1 ABI,"
		case 1:
			s += " Power ELF V1 ABI,"
		case 2:
			s += " OpenPOWER ELF V2 ABI,"
		}
		return s
	case 40:
		s := "ARM,"
		if h.class == 1 { // the EABI flags are only decoded for 32-bit ARM
			switch h.flags & 0xff000000 {
			case 0x04000000:
				s += " EABI4"
			case 0x05000000:
				s += " EABI5"
			}
			if h.flags&0x00800000 != 0 {
				s += " BE8"
			}
			if h.flags&0x00400000 != 0 {
				s += " LE8"
			}
		}
		return s
	case 62:
		return "x86-64,"
	case 183:
		return "ARM aarch64,"
	case 243:
		s := "UCB RISC-V,"
		if h.flags&0x00000001 != 0 {
			s += " RVC,"
		}
		if h.flags&0x00000008 != 0 {
			s += " RVE,"
		}
		switch h.flags & 0x00000006 {
		case 0:
			s += " soft-float ABI,"
		case 2:
			s += " single-float ABI,"
		case 4:
			s += " double-float ABI,"
		case 6:
			s += " quad-float ABI,"
		}
		return s
	}
	return ""
}

// elfState carries the running description and the "already reported this"
// flags that file(1) keeps in its magic_set while walking notes.
type elfState struct {
	det strings.Builder

	f     *elf.File
	ra    io.ReaderAt
	hdr   elfHdr
	fsize int64

	isCore       bool
	didOSNote    bool
	didBuildID   bool
	didCore      bool
	didCoreStyle bool
	didAuxv      bool
	didPax       bool
	didNetBSDTag map[uint32]bool
	didNetBSDUnk bool
	coreStyle    int

	notes int // remaining note budget
}

func (s *elfState) printf(format string, a ...any) {
	fmt.Fprintf(&s.det, format, a...)
}

// elfAnalyse produces the full description. It returns nil when the file
// cannot be opened or parsed, so the caller can fall back to the header.
func elfAnalyse(buf []byte, path string) *magicResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil
	}

	st := &elfState{
		f:            ef,
		ra:           f,
		hdr:          parseELFHdr(buf),
		fsize:        fi.Size(),
		notes:        elfNotesMax,
		didNetBSDTag: map[uint32]bool{},
	}

	// file(1) seeds the PIE decision from the file's own execute bits and
	// then lets DT_FLAGS_1 override it. Windows never reports execute bits,
	// which is the right answer there: without a .dynamic section telling us
	// otherwise, an ET_DYN image is a shared library.
	pie := fi.Mode().Perm()&0111 != 0

	switch st.hdr.etype {
	case 4: // ET_CORE
		st.isCore = true
		st.corePhdrs()
	case 2, 3: // ET_EXEC, ET_DYN
		st.execPhdrs(&pie)
		st.sections()
	case 1: // ET_REL
		st.sections()
	}

	return elfResult(st.hdr, pie, st.det.String())
}

// readSeg returns up to elfSegReadMax bytes of a program header's payload.
func readSeg(p *elf.Prog) []byte {
	n := p.Filesz
	if n > elfSegReadMax {
		n = elfSegReadMax
	}
	b := make([]byte, n)
	got, _ := io.ReadFull(p.Open(), b)
	return b[:got]
}

// execPhdrs walks the program headers of an executable or shared image to
// decide how it is linked, and reports its interpreter.
func (s *elfState) execPhdrs(pie *bool) {
	if len(s.f.Progs) == 0 {
		s.det.WriteString(", no program header")
		return
	}

	var (
		interp    string
		dynamic   bool
		sawFlags1 bool
		need      int
	)

	for _, p := range s.f.Progs {
		switch p.Type {
		case elf.PT_DYNAMIC:
			dynamic = true
			*pie = false
			s.dynamic(readSeg(p), &sawFlags1, &need, pie)

		case elf.PT_NOTE:
			if s.hdr.shnum != 0 {
				continue // the section-header walk covers these
			}
			align := p.Align
			if align&0x80000000 != 0 || align < 4 {
				s.printf(", invalid note alignment %#x", align)
				align = 4
			}
			s.walkNotes(readSeg(p), int(align))

		case elf.PT_INTERP:
			need++
			b := readSeg(p)
			if len(b) > 0 && b[0] != 0 {
				b[len(b)-1] = 0
				interp = cstring(b, 0)
			} else {
				interp = "*empty*"
			}
		}
	}

	style := "statically"
	if dynamic {
		// A dynamic image with no interpreter and no DT_NEEDED entries has
		// nothing to link against at run time: it is a static PIE.
		if sawFlags1 && need == 0 {
			style = "static-pie"
		} else {
			style = "dynamically"
		}
	}
	s.printf(", %s linked", style)
	if interp != "" {
		s.printf(", interpreter %s", interp)
	}
}

// dynamic scans .dynamic entries for the two tags that shape the description.
func (s *elfState) dynamic(b []byte, sawFlags1 *bool, need *int, pie *bool) {
	entry := 8
	if s.hdr.class == 2 {
		entry = 16
	}
	for off := 0; off+entry <= len(b); off += entry {
		var tag, val uint64
		if s.hdr.class == 2 {
			tag = s.hdr.bo.Uint64(b[off:])
			val = s.hdr.bo.Uint64(b[off+8:])
		} else {
			tag = uint64(s.hdr.bo.Uint32(b[off:]))
			val = uint64(s.hdr.bo.Uint32(b[off+4:]))
		}
		switch tag {
		case dtFlags1:
			*sawFlags1 = true
			*pie = val&df1PIE != 0
		case dtNeeded:
			*need++
		}
	}
}

// corePhdrs walks the note segments of a core dump.
func (s *elfState) corePhdrs() {
	for _, p := range s.f.Progs {
		if p.Type != elf.PT_NOTE {
			continue
		}
		if uint64(s.fsize) < p.Off {
			continue
		}
		s.walkNotes(readSeg(p), 4)
	}
}

// sections walks the section headers for notes, debug info and symbol tables.
func (s *elfState) sections() {
	if s.hdr.shnum == 0 {
		s.det.WriteString(", no section header")
		return
	}

	stripped := true
	hasDebugInfo := false

	for _, sec := range s.f.Sections {
		name := sec.Name
		if len(name) > 49 { // file(1) reads section names into a char[50]
			name = name[:49]
		}
		if name == ".debug_info" {
			hasDebugInfo = true
			stripped = false
		}
		if sec.Type == elf.SHT_SYMTAB {
			stripped = false
			continue
		}
		if uint64(s.fsize) < sec.Offset {
			continue
		}
		if sec.Type == elf.SHT_NOTE {
			if sec.Offset+sec.Size > uint64(s.fsize) {
				s.printf(", note offset/size %#x+%#x exceeds file size %#x",
					sec.Offset, sec.Size, s.fsize)
				return
			}
			data, err := sec.Data()
			if err != nil {
				s.printf(", can't read elf note at %d", sec.Offset)
				return
			}
			s.walkNotes(data, 4)
		}
	}

	if hasDebugInfo {
		s.det.WriteString(", with debug_info")
	}
	if stripped {
		s.det.WriteString(", stripped")
	} else {
		s.det.WriteString(", not stripped")
	}
}

// walkNotes iterates the note records packed into b.
func (s *elfState) walkNotes(b []byte, align int) {
	for off := 0; off < len(b); {
		next := s.note(b, off, align)
		if next == 0 || next <= off {
			break
		}
		off = next
	}
}

func elfAlign(v, align int) int {
	if align <= 0 {
		align = 4
	}
	return ((v + align - 1) / align) * align
}

// note decodes one note record and returns the offset of the next one, or 0
// to stop walking.
func (s *elfState) note(b []byte, offset, align int) int {
	if s.notes == 0 {
		return 0
	}
	s.notes--

	const nhdr = 12 // namesz, descsz, type — 32-bit words in both ELF classes
	size := len(b)
	if offset+nhdr > size {
		return offset + nhdr
	}
	namesz := int(s.hdr.bo.Uint32(b[offset:]))
	descsz := int(s.hdr.bo.Uint32(b[offset+4:]))
	ntype := s.hdr.bo.Uint32(b[offset+8:])
	offset += nhdr

	if namesz == 0 && descsz == 0 {
		if offset >= size {
			return offset
		}
		return size
	}
	if namesz < 0 || descsz < 0 { // the 0x80000000 sanity checks in file(1)
		s.det.WriteString(", bad note size")
		return 0
	}

	noff := offset
	doff := elfAlign(offset+namesz, align)
	if offset+namesz > size {
		return doff
	}
	next := elfAlign(doff+descsz, align)
	if doff+descsz > size {
		if next >= size {
			return next
		}
		return size
	}

	name := cstring(b, noff)
	desc := b[doff : doff+descsz]

	if !s.didOSNote && s.osNote(name, namesz, ntype, desc) {
		return next
	}
	if !s.didBuildID && s.buildIDNote(name, namesz, ntype, desc) {
		return next
	}
	if !s.didPax && s.paxNote(name, namesz, ntype, desc) {
		return next
	}
	if !s.didCore && s.coreNote(name, namesz, ntype, b, doff, descsz) {
		return next
	}
	if !s.didAuxv && s.auxvNote(ntype, desc) {
		return next
	}
	if namesz == 7 && name == "NetBSD" {
		s.netbsdNote(ntype, desc)
	}
	return next
}

// osNote reports the "for <OS> <version>" tail contributed by an ABI-tag note.
func (s *elfState) osNote(name string, namesz int, ntype uint32, desc []byte) bool {
	switch {
	case namesz == 5 && name == "SuSE" && ntype == ntGNUABITag && len(desc) == 2:
		s.didOSNote = true
		s.printf(", for SuSE %d.%d", desc[0], desc[1])
		return true

	case namesz == 4 && name == "GNU" && ntype == ntGNUABITag && len(desc) == 16:
		s.didOSNote = true
		s.det.WriteString(", for GNU/")
		switch s.hdr.bo.Uint32(desc[0:]) {
		case 0:
			s.det.WriteString("Linux")
		case 1:
			s.det.WriteString("Hurd")
		case 2:
			s.det.WriteString("Solaris")
		case 3:
			s.det.WriteString("kFreeBSD")
		case 4:
			s.det.WriteString("kNetBSD")
		default:
			s.det.WriteString("<unknown>")
		}
		s.printf(" %d.%d.%d", s.hdr.bo.Uint32(desc[4:]),
			s.hdr.bo.Uint32(desc[8:]), s.hdr.bo.Uint32(desc[12:]))
		return true

	case namesz == 7 && name == "NetBSD" && ntype == ntNetBSDVer && len(desc) == 4:
		s.didOSNote = true
		s.netbsdVersion(s.hdr.bo.Uint32(desc))
		return true

	case namesz == 8 && name == "FreeBSD" && ntype == ntFreeBSDVer && len(desc) == 4:
		s.didOSNote = true
		s.freebsdVersion(s.hdr.bo.Uint32(desc))
		return true

	case namesz == 8 && name == "OpenBSD" && ntype == ntOpenBSDVer && len(desc) == 4:
		s.didOSNote = true
		s.det.WriteString(", for OpenBSD") // the note content is always 0
		return true

	case namesz == 10 && name == "DragonFly" && ntype == ntDragonFlyVer && len(desc) == 4:
		s.didOSNote = true
		d := s.hdr.bo.Uint32(desc)
		s.printf(", for DragonFly %d.%d.%d", d/100000, d/10000%10, d%10000)
		return true
	}
	return false
}

// netbsdVersion decodes __NetBSD_Version__ (MMmmrrpp00).
func (s *elfState) netbsdVersion(d uint32) {
	s.det.WriteString(", for NetBSD")
	if d <= 100000000 {
		return
	}
	patch := (d / 100) % 100
	rel := (d / 10000) % 100
	min := (d / 1000000) % 100
	maj := d / 100000000
	s.printf(" %d.%d", maj, min)
	switch {
	case rel == 0 && patch != 0:
		s.printf(".%d", patch)
	case rel != 0:
		for rel > 26 {
			s.det.WriteString("Z")
			rel -= 26
		}
		s.printf("%c", 'A'+rel-1)
	}
}

// freebsdVersion decodes __FreeBSD_version.
func (s *elfState) freebsdVersion(d uint32) {
	s.det.WriteString(", for FreeBSD")
	switch {
	case d == 460002:
		s.det.WriteString(" 4.6.2")
	case d < 460100:
		s.printf(" %d.%d", d/100000, d/10000%10)
		if d/1000%10 > 0 {
			s.printf(".%d", d/1000%10)
		}
		if d%1000 > 0 || d%100000 == 0 {
			s.printf(" (%d)", d)
		}
	case d < 500000:
		s.printf(" %d.%d", d/100000, d/10000%10+d/1000%10)
		if d/100%10 > 0 {
			s.printf(" (%d)", d)
		} else if d/10%10 > 0 {
			s.printf(".%d", d/10%10)
		}
	default:
		s.printf(" %d.%d", d/100000, d/1000%100)
		if d/100%10 > 0 || d%100000/100 == 0 {
			s.printf(" (%d)", d)
		} else if d/10%10 > 0 {
			s.printf(".%d", d/10%10)
		}
	}
}

// buildIDNote reports the GNU or Go build ID.
func (s *elfState) buildIDNote(name string, namesz int, ntype uint32, desc []byte) bool {
	if namesz == 4 && name == "GNU" && ntype == ntGNUBuildID && len(desc) >= 4 && len(desc) <= 20 {
		s.didBuildID = true
		btype := "unknown"
		switch len(desc) {
		case 8:
			btype = "xxHash"
		case 16:
			btype = "md5/uuid"
		case 20:
			btype = "sha1"
		}
		s.printf(", BuildID[%s]=", btype)
		for _, c := range desc {
			s.printf("%02x", c)
		}
		return true
	}
	// The Go linker pads its note name to four bytes, so namesz is 4 here too.
	// Unlike the GNU case this does not consume the build-ID slot: a Go binary
	// carries both notes and file(1) reports both.
	if namesz == 4 && name == "Go" && ntype == ntGoBuildID && len(desc) < 128 {
		s.printf(", Go BuildID=%s", cstring(desc, 0))
		return true
	}
	return false
}

// paxNote reports NetBSD's PaX feature flags.
func (s *elfState) paxNote(name string, namesz int, ntype uint32, desc []byte) bool {
	if namesz != 4 || name != "PaX" || ntype != ntNetBSDPax || len(desc) != 4 {
		return false
	}
	s.didPax = true
	pax := [...]string{"+mprotect", "-mprotect", "+segvguard", "-segvguard", "+ASLR", "-ASLR"}
	d := s.hdr.bo.Uint32(desc)
	if d != 0 {
		s.det.WriteString(", PaX: ")
	}
	did := 0
	for i, p := range pax {
		if d&(1<<uint(i)) == 0 {
			continue
		}
		if did > 0 {
			s.det.WriteString(",")
		}
		s.det.WriteString(p)
		did++
	}
	return true
}

// coreNote reports the core-dump flavour and the name of the process that
// dumped. b/doff/descsz are passed rather than a desc slice because the
// process-name scan is allowed to run past the end of the note description
// and into the rest of the note buffer, exactly as file(1) does.
func (s *elfState) coreNote(name string, namesz int, ntype uint32, b []byte, doff, descsz int) bool {
	style := -1
	switch {
	case (namesz == 4 && strings.HasPrefix(name, "CORE")) || (namesz == 5 && name == "CORE"):
		style = coreStyleSVR4
	case namesz == 8 && name == "FreeBSD":
		style = coreStyleFreeBSD
	case namesz >= 11 && strings.HasPrefix(name, "NetBSD-CORE"):
		style = coreStyleNetBSD
	}

	if style != -1 && !s.didCoreStyle {
		s.printf(", %s-style", coreStyleNames[style])
		s.didCoreStyle = true
		s.coreStyle = style
	}

	switch style {
	case coreStyleNetBSD:
		// The NT_NETBSD_CORE_PROCINFO decode is not implemented; the
		// "NetBSD-style" tag above is all winfile reports for these.
		return false

	case coreStyleFreeBSD:
		if ntype != ntPrpsinfo || !s.isCore {
			return false
		}
		argoff := 4 + 4 + 8 + 17
		if s.hdr.class == 1 {
			argoff = 4 + 4 + 17
		}
		if doff+argoff >= len(b) {
			return false
		}
		s.printf(", from '%.80s'", cstring(b, doff+argoff))
		pidoff := argoff + 81 + 2
		if doff+pidoff+4 <= len(b) {
			s.printf(", pid=%d", s.hdr.bo.Uint32(b[doff+pidoff:]))
		}
		s.didCore = true
		return false

	case coreStyleSVR4:
		if ntype != ntPrpsinfo || !s.isCore {
			return false
		}
		return s.corePrpsinfo(b, doff, descsz)
	}
	return false
}

// corePrpsinfo hunts for the 16-character process name inside an NT_PRPSINFO
// note. Its offset varies by platform, so several candidates are tried,
// largest first, and rejected unless they hold printable characters.
func (s *elfState) corePrpsinfo(b []byte, doff, descsz int) bool {
	offsets := prpsoffsets64
	if s.hdr.class == 1 {
		offsets = prpsoffsets32
	}
	size := len(b)

	for i := 0; i < len(offsets); i++ {
		reloffset := offsets[i]
		noffset := doff + reloffset
		ok := true
		for j := 0; j < 16; j, noffset, reloffset = j+1, noffset+1, reloffset+1 {
			if noffset >= size || reloffset >= descsz {
				ok = false
				break
			}
			c := b[noffset]
			if c == 0 {
				// A NUL at the very start means this is not the name.
				if j == 0 {
					ok = false
				}
				break
			}
			if !isPrint(c) || isQuote(c) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}

		// The match may sit in the middle of a longer string; prefer an
		// earlier offset when everything between the two is printable.
		for k := i + 1; k < len(offsets); k++ {
			if offsets[k] >= offsets[i] {
				continue
			}
			adjust := true
			for no := doff + offsets[k]; no < doff+offsets[i]; no++ {
				if no >= size || !isPrint(b[no]) {
					adjust = false
					break
				}
			}
			if adjust {
				i = k
			}
		}

		start := doff + offsets[i]
		end := start
		for end < size && b[end] != 0 && isPrint(b[end]) {
			end++
		}
		// Linux appends a space to the recorded command line.
		for end > start && isSpace(b[end-1]) {
			end--
		}
		s.printf(", from '%s'", string(b[start:end]))
		s.didCore = true
		return true
	}
	return false
}

// auxvNote reports the identity fields of an SVR4 core's auxiliary vector.
func (s *elfState) auxvNote(ntype uint32, desc []byte) bool {
	if !s.isCore || !s.didCoreStyle || s.coreStyle != coreStyleSVR4 {
		return false
	}
	if ntype != ntAuxv {
		return false
	}
	s.didAuxv = true

	elsize := 8
	if s.hdr.class == 2 {
		elsize = 16
	}
	for off, n := 0, 0; off+elsize <= len(desc); off += elsize {
		if n++; n > elfAuxvMax {
			return true
		}
		var atype, val uint64
		if s.hdr.class == 2 {
			atype = s.hdr.bo.Uint64(desc[off:])
			val = s.hdr.bo.Uint64(desc[off+8:])
		} else {
			atype = uint64(s.hdr.bo.Uint32(desc[off:]))
			val = uint64(s.hdr.bo.Uint32(desc[off+4:]))
		}

		var tag string
		isString := false
		switch atype {
		case atExecfn:
			tag, isString = "execfn", true
		case atPlatform:
			tag, isString = "platform", true
		case atUID:
			tag = "real uid"
		case atGID:
			tag = "real gid"
		case atEUID:
			tag = "effective uid"
		case atEGID:
			tag = "effective gid"
		default:
			continue
		}

		if isString {
			if str, ok := s.stringAtVaddr(val); ok {
				s.printf(", %s: '%s'", tag, str)
			}
			continue
		}
		s.printf(", %s: %d", tag, int32(val))
	}
	return true
}

// stringAtVaddr resolves a virtual address to a file offset via the program
// headers and reads the NUL-terminated string there.
func (s *elfState) stringAtVaddr(vaddr uint64) (string, bool) {
	var off int64 = -1
	for _, p := range s.f.Progs {
		if uint64(s.fsize) < p.Off {
			continue
		}
		if vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Filesz {
			off = int64(p.Off + (vaddr - p.Vaddr))
			break
		}
	}
	if off < 0 {
		return "", false
	}
	b := make([]byte, 256)
	n, _ := s.ra.ReadAt(b, off)
	if n <= 0 {
		return "", false
	}
	b = b[:n]
	b[len(b)-1] = 0

	// Anything unprintable before the terminator means this is not a string.
	i := 0
	for i < len(b) && b[i] != 0 {
		if !isPrint(b[i]) {
			return "", false
		}
		i++
	}
	return string(b[:i]), true
}

// netbsdNote reports the remaining NetBSD-specific note tags.
func (s *elfState) netbsdNote(ntype uint32, desc []byte) {
	if len(desc) > 100 {
		desc = desc[:100]
	}
	var tag string
	switch ntype {
	case ntNetBSDVer:
		return
	case ntNetBSDMarch:
		tag = "compiled for"
	case ntNetBSDCmodel:
		tag = "compiler model"
	case ntNetBSDEmul:
		tag = "emulation:"
	default:
		if s.didNetBSDUnk {
			return
		}
		s.didNetBSDUnk = true
		s.printf(", note=%d", ntype)
		return
	}
	if s.didNetBSDTag[ntype] {
		return
	}
	s.didNetBSDTag[ntype] = true
	s.printf(", %s: %s", tag, string(desc))
}

// cstring reads the NUL-terminated string starting at off.
func cstring(b []byte, off int) string {
	if off < 0 || off >= len(b) {
		return ""
	}
	for i := off; i < len(b); i++ {
		if b[i] == 0 {
			return string(b[off:i])
		}
	}
	return string(b[off:])
}

func isPrint(c byte) bool { return c >= 0x20 && c < 0x7f }

func isQuote(c byte) bool { return c == '\'' || c == '"' || c == '`' }

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}
