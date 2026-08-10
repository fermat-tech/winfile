// winfile is a Windows port of the classic Unix `file` command.
//
// It identifies the type of one or more files by examining their content
// (magic bytes, encoding heuristics, and structural markers) rather than
// relying on file extensions alone. Output is compatible with the GNU file
// command so it can be used as a drop-in replacement in scripts and pipelines
// on Windows.
//
// Usage:
//
//	winfile [OPTION...] FILE...
//
// Common options:
//
//	-b              brief output (no filename prefix)
//	-i              output MIME type string (e.g. image/png; charset=binary)
//	--mime-type     output MIME type only
//	--mime-encoding output charset / encoding only
//	--extension     output slash-separated list of valid extensions
//	-f FILE         read filenames from FILE (one per line)
//	-L              follow symbolic links
//	-z              look inside compressed files (gzip, bzip2)
//	-Z              like -z but omit the compression wrapper from the description
//	-0              NUL-terminate output records (for use with xargs -0)
//
// See [usage] for the full option list.
//
// Detection coverage
//
// Binary formats: PE (EXE/DLL), ELF (reported in GNU file's full detail —
// linkage, interpreter, build ID, ABI tag, stripped state, core-dump
// provenance; see elf.go), Mach-O, ZIP and OOXML derivatives
// (DOCX/XLSX/PPTX/JAR/APK/EPUB), gzip, bzip2, XZ, zstd, LZ4, 7-Zip, RAR,
// tar (POSIX ustar), PNG, JPEG, GIF, BMP, TIFF, WebP, AVIF/HEIF, ICO, PDF,
// PostScript, OLE2 (legacy Office), SQLite, Java .class, MKV/WebM, MP4/MOV,
// AVI, FLAC, Ogg (Vorbis/Opus/Theora), WAV, MIDI, TTF/OTF/WOFF/WOFF2, PEM
// certificates, and many more.
//
// Text formats: ASCII, UTF-8, UTF-16 LE/BE (BOM-detected), UTF-32 LE/BE;
// Go, Python, JavaScript/TypeScript, JSX/TSX, Java, C/C++, C#, Rust, Ruby,
// PHP, Perl, Shell, PowerShell, Batch, Lua, HTML, XML, SVG, CSS/SCSS, JSON,
// YAML, TOML, Markdown, SQL, Dockerfile, Makefile, and more—detected by
// content first, extension as a secondary hint.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

// version is stamped at build time by the release process via
// -ldflags "-X main.version=vX.Y.Z". A plain `go build` leaves it "dev", so an
// unstamped binary says so instead of claiming a release it is not.
var version = "dev"

type options struct {
	brief            bool   // -b
	mime             bool   // -i
	mimeType         bool   // --mime-type
	mimeEncoding     bool   // --mime-encoding
	extension        bool   // --extension
	filesFrom        string // -f
	separator        string // -F
	dereference      bool   // -L
	noBuffer         bool   // -n
	noPad            bool   // -N
	printNul         bool   // -0
	preserveDate     bool   // -p
	raw              bool   // -r
	specialFiles     bool   // -s  (treat block/char/fifo as regular)
	uncompress       bool   // -z
	uncompressNoreport bool // -Z
	keepGoing        bool   // -k (no-op; we always check all tests)
	color            bool
	excludeTests     []string // -e (stored but minimal effect)
}

var programName string

func init() {
	programName = strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0]))
}

func main() {
	var opts options

	// Flags
	flag.BoolVar(&opts.brief, "b", false, "do not prepend filenames to output lines")
	flag.BoolVar(&opts.brief, "brief", false, "do not prepend filenames to output lines")
	flag.BoolVar(&opts.mime, "i", false, "output MIME type strings")
	flag.BoolVar(&opts.mime, "mime", false, "output MIME type strings")
	flag.BoolVar(&opts.mimeType, "mime-type", false, "output MIME type only")
	flag.BoolVar(&opts.mimeEncoding, "mime-encoding", false, "output charset/encoding only")
	flag.BoolVar(&opts.extension, "extension", false, "output a slash-separated list of valid extensions")
	flag.StringVar(&opts.filesFrom, "f", "", "read file names from `file`")
	flag.StringVar(&opts.filesFrom, "files-from", "", "read file names from `file`")
	flag.StringVar(&opts.separator, "F", ":", "use `string` as separator between file name and result")
	flag.StringVar(&opts.separator, "separator", ":", "use `string` as separator between file name and result")
	flag.BoolVar(&opts.dereference, "L", false, "follow symlinks")
	flag.BoolVar(&opts.dereference, "dereference", false, "follow symlinks")
	flag.BoolVar(&opts.noBuffer, "n", false, "do not buffer output (flush after each file)")
	flag.BoolVar(&opts.noBuffer, "no-buffer", false, "do not buffer output (flush after each file)")
	flag.BoolVar(&opts.noPad, "N", false, "do not pad filenames")
	flag.BoolVar(&opts.noPad, "no-pad", false, "do not pad filenames")
	flag.BoolVar(&opts.printNul, "0", false, "terminate output records with NUL, not newline")
	flag.BoolVar(&opts.printNul, "print0", false, "terminate output records with NUL, not newline")
	flag.BoolVar(&opts.preserveDate, "p", false, "preserve access times")
	flag.BoolVar(&opts.preserveDate, "preserve-date", false, "preserve access times")
	flag.BoolVar(&opts.raw, "r", false, "don't translate unprintable characters to \\ooo")
	flag.BoolVar(&opts.raw, "raw", false, "don't translate unprintable characters to \\ooo")
	flag.BoolVar(&opts.specialFiles, "s", false, "treat special (non-regular) files as ordinary files")
	flag.BoolVar(&opts.specialFiles, "special-files", false, "treat special (non-regular) files as ordinary files")
	flag.BoolVar(&opts.uncompress, "z", false, "try to look inside compressed files")
	flag.BoolVar(&opts.uncompress, "uncompress", false, "try to look inside compressed files")
	flag.BoolVar(&opts.uncompressNoreport, "Z", false, "try to look inside compressed files, but omit compression type")
	flag.BoolVar(&opts.uncompressNoreport, "uncompress-noreport", false, "try to look inside compressed files, but omit compression type")
	flag.BoolVar(&opts.keepGoing, "k", false, "don't stop at first match (informational, always done)")
	flag.BoolVar(&opts.keepGoing, "keep-going", false, "don't stop at first match")
	showVersion := flag.Bool("v", false, "print version and exit")
	showVersion2 := flag.Bool("version", false, "print version and exit")

	// -e exclude (can repeat) — store but we don't distinguish tests internally
	var excludes excludeFlag
	flag.Var(&excludes, "e", "exclude `testname` from the list of tests made")
	flag.Var(&excludes, "exclude", "exclude `testname` from the list of tests made")

	flag.Usage = usage
	flag.Parse()

	if *showVersion || *showVersion2 {
		fmt.Fprintf(os.Stdout, "%s-%s\n", programName, version)
		os.Exit(0)
	}

	opts.excludeTests = []string(excludes)
	if opts.uncompressNoreport {
		opts.uncompress = true
	}

	// Colour support (NO_COLOR or not a tty suppresses colour)
	stdout := colorable.NewColorableStdout()
	opts.color = isatty.IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == ""

	// Collect file paths
	var paths []string

	if opts.filesFrom != "" {
		listed, err := readPathsFromFile(opts.filesFrom)
		if err != nil {
			fatalf("cannot read file list %q: %v", opts.filesFrom, err)
		}
		paths = append(paths, listed...)
	}
	paths = append(paths, flag.Args()...)

	if len(paths) == 0 {
		usage()
		os.Exit(1)
	}

	// Compute max name width for padding (like GNU file)
	maxLen := 0
	if !opts.brief && !opts.noPad {
		for _, p := range paths {
			if len(p) > maxLen {
				maxLen = len(p)
			}
		}
	}

	w := bufio.NewWriter(stdout)

	exitCode := 0
	for _, p := range paths {
		res := analyseFile(p, &opts)
		printResult(w, res, &opts, maxLen)
		if opts.noBuffer {
			w.Flush()
		}
		if res.err != "" {
			exitCode = 1
		}
	}

	w.Flush()
	os.Exit(exitCode)
}

func printResult(w io.Writer, res fileResult, opts *options, maxLen int) {
	if res.err != "" {
		label := res.path + opts.separator
		if !opts.brief {
			fmt.Fprintf(w, "%s ERROR: %s", label, res.err)
		} else {
			fmt.Fprintf(w, "ERROR: %s", res.err)
		}
		writeTerminator(w, opts)
		return
	}

	output := formatOutput(res, opts)

	if opts.brief {
		fmt.Fprint(w, output)
	} else {
		sep := opts.separator
		if !opts.noPad && maxLen > 0 {
			name := res.path + sep
			pad := maxLen + len(sep) + 1 - len(name)
			if pad < 1 {
				pad = 1
			}
			fmt.Fprintf(w, "%s%s%s%s", res.path, sep, strings.Repeat(" ", pad), output)
		} else {
			fmt.Fprintf(w, "%s%s %s", res.path, sep, output)
		}
	}
	writeTerminator(w, opts)
}

func formatOutput(res fileResult, opts *options) string {
	if opts.extension {
		if res.ext == "" {
			return "???"
		}
		return res.ext
	}

	if opts.mimeType {
		if res.mime == "" {
			return "application/octet-stream"
		}
		return res.mime
	}

	if opts.mimeEncoding {
		enc := res.mimeEnc
		if enc == "" {
			if strings.HasPrefix(res.mime, "text/") {
				enc = "us-ascii"
			} else {
				enc = "binary"
			}
		}
		return enc
	}

	if opts.mime || opts.mimeType {
		enc := res.mimeEnc
		if enc == "" {
			if strings.HasPrefix(res.mime, "text/") {
				enc = "us-ascii"
			} else {
				enc = "binary"
			}
		}
		mime := res.mime
		if mime == "" {
			mime = "application/octet-stream"
		}
		return mime + "; charset=" + enc
	}

	return res.desc
}

func writeTerminator(w io.Writer, opts *options) {
	if opts.printNul {
		fmt.Fprint(w, "\x00")
	} else {
		fmt.Fprintln(w)
	}
}

func readPathsFromFile(name string) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var paths []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths, sc.Err()
}

func fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, programName+": "+format+"\n", a...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [OPTION...] [FILE...]

Determine type of FILEs.

Options:
  -b, --brief            do not prepend filenames to output
  -e, --exclude TEST     exclude TEST from checks (append, soft, compress, elf, tokens, troff, text)
  --extension            print a slash-separated list of valid extensions for the file type
  -f, --files-from FILE  read input file names from FILE
  -F, --separator SEP    use SEP instead of ':' between filename and result
  -i, --mime             output MIME type string
      --mime-type        output MIME type only
      --mime-encoding    output MIME encoding only
  -k, --keep-going       don't stop at first match (always done internally)
  -L, --dereference      follow symlinks
  -n, --no-buffer        do not buffer output
  -N, --no-pad           do not pad filenames
  -0, --print0           end filenames with NUL, for use with xargs -0
  -p, --preserve-date    preserve file access dates
  -r, --raw              don't translate unprintable chars
  -s, --special-files    treat special files as ordinary
  -v, --version          output version information and exit
  -z, --uncompress       try to look inside compressed files
  -Z, --uncompress-noreport  like -z but omit the compression type report

Unsupported (Windows has no equivalent):
  -c, --checking-printout  check the parsed form of the magic file
  -l, --list               list magic strength
  -m, --magic-file FILE    use FILE as magic database

`, programName)
}

// excludeFlag allows -e to be repeated.
type excludeFlag []string

func (e *excludeFlag) String() string  { return strings.Join(*e, ",") }
func (e *excludeFlag) Set(v string) error { *e = append(*e, v); return nil }
