// detect.go is the top-level file analyser for winfile.
//
// [analyseFile] is the entry point: it stats the path, handles Windows
// special files (symlinks, directories, named pipes, sockets), opens the file,
// reads the magic-byte window, and delegates to [doAnalyse].
//
// [doAnalyse] runs the two-pass detection pipeline:
//  1. Magic-byte scan via [detectMagic] (magic.go).
//  2. Text-encoding scan via [detectText] (text.go) if magic returns nil.
//
// If neither pass succeeds the file is reported as "data" with MIME type
// application/octet-stream.
//
// Compression unwrapping (-z / -Z flags)
//
// When [options.uncompress] is set and the outer format is gzip or bzip2,
// [decompressFirst] streams the first magicBufSize bytes of the inner payload
// and runs the two-pass detection on that buffer. The outer compression type
// is appended to the description unless [options.uncompressNoreport] is set.
// XZ is identified at the outer level but inner unwrapping is not supported
// (no XZ decoder in the Go standard library).
//
// Text refinement
//
// [refineText] narrows a generic ASCII/UTF-8 result to a specific language or
// format using two signals: JSON structural heuristic first, then the file
// extension as a secondary hint. The extension table covers ~60 languages and
// markup formats. A separate base-name table handles extension-less files such
// as Makefile and Dockerfile.
//
// Access-time preservation (-p flag)
//
// When [options.preserveDate] is set, a deferred [os.Chtimes] call restores
// the modification time after the file is read. (Windows does not expose the
// atime separately via Go's os.Lstat, so mtime is used as the best available
// approximation.)
package main

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const magicBufSize = 512 + 256 // cover tar magic at offset 257 and common headers

// fileResult is the full analysis of one file.
type fileResult struct {
	path     string
	desc     string
	mime     string
	mimeEnc  string // charset or encoding for --mime-encoding
	ext      string // extension list for --extension
	isSymlink bool
	symlinkTarget string
	err      string
}

func analyseFile(path string, opts *options) fileResult {
	res := fileResult{path: path}

	// Stat — follow symlinks based on -L flag
	var fi os.FileInfo
	var err error
	var symlinkTarget string

	lfi, lerr := os.Lstat(path)
	if lerr != nil {
		res.err = lerr.Error()
		return res
	}

	if lfi.Mode()&os.ModeSymlink != 0 {
		res.isSymlink = true
		symlinkTarget, _ = os.Readlink(path)
		res.symlinkTarget = symlinkTarget
		if opts.dereference {
			fi, err = os.Stat(path)
			if err != nil {
				res.desc = "symbolic link to " + symlinkTarget + " (dangling)"
				res.mime = "inode/symlink"
				return res
			}
		} else {
			res.desc = "symbolic link to " + symlinkTarget
			res.mime = "inode/symlink"
			res.ext = "???"
			return res
		}
	} else {
		fi = lfi
	}

	mode := fi.Mode()

	// Directories
	if mode.IsDir() {
		res.desc = "directory"
		res.mime = "inode/directory"
		res.ext = "???"
		return res
	}

	// Windows special files (devices, pipes) — best effort
	if mode&os.ModeDevice != 0 || mode&os.ModeCharDevice != 0 {
		res.desc = "character special file"
		res.mime = "inode/chardevice"
		res.ext = "???"
		return res
	}
	if mode&os.ModeNamedPipe != 0 {
		res.desc = "fifo (named pipe)"
		res.mime = "inode/fifo"
		res.ext = "???"
		return res
	}
	if mode&os.ModeSocket != 0 {
		res.desc = "socket"
		res.mime = "inode/socket"
		res.ext = "???"
		return res
	}

	// Regular file
	f, err := os.Open(path)
	if err != nil {
		res.err = err.Error()
		return res
	}
	defer f.Close()

	// Preserve access time if requested
	if opts.preserveDate {
		defer func() {
			atime := lfi.ModTime() // best approximation; Windows doesn't expose atime via Go
			_ = os.Chtimes(path, atime, lfi.ModTime())
		}()
	}

	buf := make([]byte, magicBufSize)
	n, _ := f.Read(buf)
	buf = buf[:n]

	size := fi.Size()
	res = doAnalyse(path, buf, size, opts, res)
	return res
}

func doAnalyse(path string, buf []byte, size int64, opts *options, res fileResult) fileResult {
	// Try magic detection first
	mr := detectMagic(buf, size)

	if mr != nil {
		res.desc = mr.desc
		res.mime = mr.mime
		res.ext = mr.ext

		// For gzip: try to decompress and re-identify inner file (-z flag)
		if opts.uncompress && isCompressed(mr.mime) {
			inner, innerName, err := decompressFirst(buf, mr.mime, path)
			if err == nil && len(inner) > 0 {
				var innerDesc, innerMime, innerExt string
				innerMR := detectMagic(inner, int64(len(inner)))
				if innerMR != nil {
					innerDesc, innerMime, innerExt = innerMR.desc, innerMR.mime, innerMR.ext
				} else if tr2 := detectText(inner); tr2 != nil {
					innerDesc, innerMime, innerExt = tr2.desc, tr2.mime, "txt"
				}
				if innerDesc != "" {
					if opts.uncompressNoreport {
						res.desc = innerDesc
						res.mime = innerMime
						res.ext = innerExt
					} else {
						res.desc = innerDesc + " (from " + mr.desc + ")"
						if innerName != "" {
							res.desc += " named " + innerName
						}
						res.mime = innerMime
						res.ext = innerExt
					}
				}
			}
		}
		populateMIMEEnc(&res)
		return res
	}

	// Fall back to text detection
	tr := detectText(buf)
	if tr != nil {
		res.desc = tr.desc
		res.mime = tr.mime
		res.mimeEnc = tr.encoding
		if tr.hasCR {
			res.desc += " with CRLF line terminators"
		}

		// Try to narrow down the text type by extension or content
		res = refineText(res, buf, path)
		return res
	}

	// Unknown binary
	res.desc = "data"
	res.mime = "application/octet-stream"
	res.ext = "???"
	return res
}

// refineText attempts to narrow a text file to a specific type.
func refineText(res fileResult, buf []byte, path string) fileResult {
	// JSON
	if looksLikeJSON(buf) {
		res.desc = "JSON data"
		res.mime = "application/json"
		res.ext = "json"
		return res
	}

	// Look at the extension as a hint
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	switch ext {
	case "go":
		res.desc = "Go source text"
		res.mime = "text/x-go"
		res.ext = "go"
	case "py":
		res.desc = "Python source text"
		res.mime = "text/x-python"
		res.ext = "py"
	case "js", "mjs", "cjs":
		res.desc = "JavaScript source text"
		res.mime = "text/javascript"
		res.ext = "js"
	case "ts", "tsx":
		res.desc = "TypeScript source text"
		res.mime = "text/x-typescript"
		res.ext = "ts"
	case "jsx":
		res.desc = "JSX source text"
		res.mime = "text/x-jsx"
		res.ext = "jsx"
	case "java":
		res.desc = "Java source text"
		res.mime = "text/x-java"
		res.ext = "java"
	case "c", "h":
		res.desc = "C source text"
		res.mime = "text/x-c"
		res.ext = "c"
	case "cpp", "cc", "cxx", "hpp":
		res.desc = "C++ source text"
		res.mime = "text/x-c++"
		res.ext = "cpp"
	case "cs":
		res.desc = "C# source text"
		res.mime = "text/x-csharp"
		res.ext = "cs"
	case "rs":
		res.desc = "Rust source text"
		res.mime = "text/x-rust"
		res.ext = "rs"
	case "rb":
		res.desc = "Ruby source text"
		res.mime = "text/x-ruby"
		res.ext = "rb"
	case "php":
		res.desc = "PHP source text"
		res.mime = "text/x-php"
		res.ext = "php"
	case "pl", "pm":
		res.desc = "Perl source text"
		res.mime = "text/x-perl"
		res.ext = "pl"
	case "sh", "bash":
		res.desc = "Bourne shell script text"
		res.mime = "text/x-shellscript"
		res.ext = "sh"
	case "ps1", "psm1", "psd1":
		res.desc = "PowerShell script text"
		res.mime = "text/x-powershell"
		res.ext = "ps1"
	case "bat", "cmd":
		res.desc = "DOS batch file text"
		res.mime = "text/x-msdos-batch"
		res.ext = "bat"
	case "lua":
		res.desc = "Lua script text"
		res.mime = "text/x-lua"
		res.ext = "lua"
	case "r", "rmd":
		res.desc = "R script text"
		res.mime = "text/x-r"
		res.ext = "r"
	case "swift":
		res.desc = "Swift source text"
		res.mime = "text/x-swift"
		res.ext = "swift"
	case "kt", "kts":
		res.desc = "Kotlin source text"
		res.mime = "text/x-kotlin"
		res.ext = "kt"
	case "scala":
		res.desc = "Scala source text"
		res.mime = "text/x-scala"
		res.ext = "scala"
	case "hs", "lhs":
		res.desc = "Haskell source text"
		res.mime = "text/x-haskell"
		res.ext = "hs"
	case "ml", "mli":
		res.desc = "OCaml source text"
		res.mime = "text/x-ocaml"
		res.ext = "ml"
	case "ex", "exs":
		res.desc = "Elixir source text"
		res.mime = "text/x-elixir"
		res.ext = "ex"
	case "erl", "hrl":
		res.desc = "Erlang source text"
		res.mime = "text/x-erlang"
		res.ext = "erl"
	case "clj", "cljs":
		res.desc = "Clojure source text"
		res.mime = "text/x-clojure"
		res.ext = "clj"
	case "lisp", "el", "scm":
		res.desc = "Lisp source text"
		res.mime = "text/x-lisp"
		res.ext = "lisp"
	case "zig":
		res.desc = "Zig source text"
		res.mime = "text/x-zig"
		res.ext = "zig"
	case "nim":
		res.desc = "Nim source text"
		res.mime = "text/x-nim"
		res.ext = "nim"
	case "v":
		res.desc = "V source text"
		res.mime = "text/x-v"
		res.ext = "v"
	case "d":
		res.desc = "D source text"
		res.mime = "text/x-d"
		res.ext = "d"
	case "f90", "f95", "f03", "f77", "for", "f":
		res.desc = "Fortran source text"
		res.mime = "text/x-fortran"
		res.ext = "f90"
	case "html", "htm":
		res.desc = "HTML document text"
		res.mime = "text/html"
		res.ext = "html"
	case "xml":
		res.desc = "XML document text"
		res.mime = "application/xml"
		res.ext = "xml"
	case "svg":
		res.desc = "SVG Scalable Vector Graphics image"
		res.mime = "image/svg+xml"
		res.ext = "svg"
	case "css":
		res.desc = "CSS stylesheet text"
		res.mime = "text/css"
		res.ext = "css"
	case "scss", "sass":
		res.desc = "Sass/SCSS stylesheet text"
		res.mime = "text/x-scss"
		res.ext = "scss"
	case "json":
		res.desc = "JSON data"
		res.mime = "application/json"
		res.ext = "json"
	case "json5":
		res.desc = "JSON5 data"
		res.mime = "application/json"
		res.ext = "json"
	case "jsonl", "ndjson":
		res.desc = "JSON Lines data"
		res.mime = "application/x-ndjson"
		res.ext = "jsonl"
	case "yaml", "yml":
		res.desc = "YAML document text"
		res.mime = "text/x-yaml"
		res.ext = "yaml"
	case "toml":
		res.desc = "TOML document text"
		res.mime = "text/x-toml"
		res.ext = "toml"
	case "ini", "cfg", "conf":
		res.desc = "ASCII text (INI/config format)"
		res.mime = "text/plain"
		res.ext = ext
	case "md", "markdown":
		res.desc = "Markdown document text"
		res.mime = "text/markdown"
		res.ext = "md"
	case "rst":
		res.desc = "reStructuredText document text"
		res.mime = "text/x-rst"
		res.ext = "rst"
	case "tex", "latex":
		res.desc = "LaTeX document text"
		res.mime = "text/x-tex"
		res.ext = "tex"
	case "csv":
		res.desc = "CSV text"
		res.mime = "text/csv"
		res.ext = "csv"
	case "tsv":
		res.desc = "TSV text"
		res.mime = "text/tab-separated-values"
		res.ext = "tsv"
	case "sql":
		res.desc = "SQL text"
		res.mime = "application/sql"
		res.ext = "sql"
	case "proto":
		res.desc = "Protocol Buffer schema text"
		res.mime = "text/x-protobuf"
		res.ext = "proto"
	case "graphql", "gql":
		res.desc = "GraphQL schema/query text"
		res.mime = "application/graphql"
		res.ext = "graphql"
	case "makefile", "mk":
		res.desc = "makefile script text"
		res.mime = "text/x-makefile"
		res.ext = "mak"
	case "cmake":
		res.desc = "CMake script text"
		res.mime = "text/x-cmake"
		res.ext = "cmake"
	case "dockerfile":
		res.desc = "Docker build recipe text"
		res.mime = "text/x-dockerfile"
		res.ext = "dockerfile"
	case "gitignore", "gitattributes", "gitmodules":
		res.desc = "Git configuration text"
		res.mime = "text/plain"
		res.ext = "???"}

	// Check content-based heuristics for filename-without-extension cases
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "makefile", "gnumakefile":
		res.desc = "makefile script text"
		res.mime = "text/x-makefile"
		res.ext = "mak"
	case "dockerfile":
		res.desc = "Docker build recipe text"
		res.mime = "text/x-dockerfile"
		res.ext = "dockerfile"
	case "cmakelists.txt":
		res.desc = "CMake script text"
		res.mime = "text/x-cmake"
		res.ext = "cmake"
	}

	return res
}

func populateMIMEEnc(res *fileResult) {
	if res.mimeEnc != "" {
		return
	}
	// default charset for text
	if strings.HasPrefix(res.mime, "text/") {
		res.mimeEnc = "us-ascii"
	} else {
		res.mimeEnc = "binary"
	}
}

func isCompressed(mime string) bool {
	switch mime {
	case "application/gzip", "application/x-bzip2", "application/x-xz":
		return true
	}
	return false
}

// decompressFirst reads the first chunk of a compressed file.
func decompressFirst(buf []byte, mime, path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var r io.Reader
	var innerName string

	switch mime {
	case "application/gzip":
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, "", err
		}
		defer gz.Close()
		innerName = gz.Header.Name
		r = gz
	case "application/x-bzip2":
		r = bzip2.NewReader(f)
	case "application/x-xz":
		// No stdlib XZ; try to detect after decompression as TAR
		return nil, "", nil
	default:
		return nil, "", nil
	}

	inner := make([]byte, magicBufSize)
	n, _ := io.ReadFull(r, inner)
	if n == 0 {
		return nil, "", nil
	}

	// If inner looks like TAR, report it
	if n >= 262 {
		innerBuf := inner[:n]
		if bytes.Equal(innerBuf[257:262], []byte("ustar")) {
			// Peek the file name from the TAR header
			tr := tar.NewReader(bytes.NewReader(innerBuf))
			if hdr, err := tr.Next(); err == nil {
				innerName = hdr.Name
			}
		}
	}

	return inner[:n], innerName, nil
}

// mtime stores the original timestamps for -p.
func mtime(fi os.FileInfo) time.Time {
	return fi.ModTime()
}
