# winfile

`winfile` is a Windows port of the classic Unix [`file`](https://www.darwinsys.com/file/) command.
It identifies the type of one or more files by examining their **content** (magic bytes, encoding heuristics, and structural markers) rather than relying on file extensions alone. Output is compatible with GNU `file` so it drops into existing scripts and pipelines unchanged.

```
winfile [OPTION...] FILE...
```

## Installation

**Pre-built binary** — grab the latest `winfile_windows_amd64.zip` from the [Releases](https://github.com/fermat-tech/winfile/releases) page, extract `winfile.exe`, and put it on your `PATH`.

**From source** (requires Go 1.21+):

```powershell
go install github.com/fermat-tech/winfile@latest
```

**Build locally:**

```powershell
git clone https://github.com/fermat-tech/winfile
cd winfile
go build -o winfile.exe .
```

## Usage

```
winfile [OPTION...] FILE...
```

| Option | Long form | Description |
|--------|-----------|-------------|
| `-b` | `--brief` | Omit filename prefix |
| `-i` | `--mime` | Output MIME type string (e.g. `image/png; charset=binary`) |
| | `--mime-type` | Output MIME type only |
| | `--mime-encoding` | Output charset / encoding only |
| | `--extension` | Output slash-separated list of valid extensions |
| `-f FILE` | `--files-from FILE` | Read filenames from FILE (one per line) |
| `-F SEP` | `--separator SEP` | Use SEP instead of `:` between filename and result |
| `-L` | `--dereference` | Follow symbolic links |
| `-n` | `--no-buffer` | Flush output after each file |
| `-N` | `--no-pad` | Don't pad filenames to a common width |
| `-0` | `--print0` | NUL-terminate output records (for `xargs -0`) |
| `-p` | `--preserve-date` | Preserve file access time |
| `-r` | `--raw` | Don't translate unprintable characters |
| `-s` | `--special-files` | Treat special files as ordinary |
| `-z` | `--uncompress` | Look inside compressed files |
| `-Z` | `--uncompress-noreport` | Like `-z` but omit the compression type |
| `-k` | `--keep-going` | Don't stop at first match (always done) |
| `-e TEST` | `--exclude TEST` | Exclude a test by name (accepted, no-op) |
| `-v` | `--version` | Print version and exit |

### Examples

```powershell
# Basic identification
winfile photo.jpg report.pdf archive.zip

# MIME types for HTTP content-type scripting
winfile --mime-type *.dll

# Inspect compressed files
winfile -z logs.gz

# Pipe-friendly NUL termination
winfile -0 -b *.exe | xargs -0 -I{} echo "Found: {}"

# Feed a list of paths from another tool
Get-ChildItem -Recurse -Filter *.bin | % FullName | winfile -f -

# Brief + separator for custom formatting
winfile -b -F " => " main.go go.mod

# Encoding detection
winfile --mime-encoding *.txt *.json
```

### Sample output

```
winfile.exe:   PE32+ executable (x86-64), for MS Windows
report.pdf:    PDF document, version 1.7
photo.jpg:     JPEG image data, Exif standard
archive.zip:   Zip archive data
notes.txt:     UTF-8 Unicode text with CRLF line terminators
empty.dat:     empty
script.py:     Python script text executable
main.go:       Go source text
ntdll.dll:     PE32+ DLL (x86-64), for MS Windows
```

## Detected formats

### Binary / structured

| Category | Formats |
|----------|---------|
| Executables | PE (EXE/DLL/OBJ), ELF, Mach-O |
| Archives | ZIP, gzip, bzip2, XZ, zstd, LZ4, lzip, LZMA, 7-Zip, RAR, tar (ustar/GNU), Cabinet, ar |
| Office (OOXML) | DOCX, XLSX, PPTX (detected inside ZIP) |
| Office (legacy) | OLE2 compound document (DOC, XLS, PPT, MSG) |
| Images | PNG, JPEG, GIF, BMP, TIFF, WebP, AVIF, HEIF/HEIC, ICO, CUR, JPEG 2000, PSD, XCF, PPM/PGM/PBM, SVG |
| Audio | WAV, FLAC, Ogg (Vorbis/Opus/Theora/Speex), MP3, MIDI, AIFF, AU, APE, WavPack |
| Video | AVI, MP4/M4V/MOV/3GP, MKV, WebM, FLV, ASF/WMV, MPEG, H.264 |
| Documents | PDF, PostScript, RTF |
| Fonts | TTF, OTF, WOFF, WOFF2 |
| Databases | SQLite 3, Microsoft Access |
| Disk images | ISO 9660, MBR boot sector, VMDK, VHD, VHDX, QCOW2 |
| Bytecode | Java `.class`, Python `.pyc` |
| Crypto | PEM, DER (X.509) |
| Containers | EPUB, JAR, APK (detected inside ZIP) |

### Text / source code

Encoding detection: **UTF-32** (LE/BE BOM), **UTF-16** (LE/BE BOM), **UTF-8** (with or without BOM), **ASCII**.
CRLF vs LF line endings are reported.

Source languages detected: Go, Python, JavaScript, TypeScript, JSX/TSX, Java, C, C++, C#, Rust, Ruby, PHP, Perl, Shell (bash/sh/zsh/fish), PowerShell, DOS Batch, Lua, R, Swift, Kotlin, Scala, Haskell, OCaml, Elixir, Erlang, Clojure, Lisp, Zig, Nim, V, D, Fortran.

Markup & data: HTML, XML, SVG, CSS/SCSS, JSON, JSON Lines, YAML, TOML, Markdown, reStructuredText, LaTeX, CSV, TSV, SQL, Protocol Buffers, GraphQL.

Build & tooling: Makefile, CMake, Dockerfile, `.gitignore`.

Shebang detection: identifies the interpreter from `#!` lines for scripts with no extension.

## Windows-specific notes

The following GNU `file` options have no Windows equivalent and are **not supported**:

| Option | Reason |
|--------|--------|
| `-m FILE` / `--magic-file` | winfile uses compiled-in signatures, not libmagic's database format |
| `-c` / `--checking-printout` | no magic file to syntax-check |
| `-l` / `--list` | no magic strength table |
| Block/character device types | Windows has no `/dev` device tree |

Everything else — MIME output, compression unwrapping, symlink following, padding, NUL termination, files-from, separator, preserve-date — works exactly as on Linux.

## Part of the win* toolkit

`winfile` is one of several GNU/Unix tool ports for Windows maintained under [github.com/fermat-tech](https://github.com/fermat-tech):

| Tool | Equivalent |
|------|-----------|
| [winegrep](https://github.com/fermat-tech/winegrep) | `egrep` |
| [winfind](https://github.com/fermat-tech/winfind) | `find` |
| [winls](https://github.com/fermat-tech/winls) | `ls` |
| [winwc](https://github.com/fermat-tech/winwc) | `wc` |
| [winwhich](https://github.com/fermat-tech/winwhich) | `which` |
| [winless](https://github.com/fermat-tech/winless) | `less` |
| [winheadtail](https://github.com/fermat-tech/winheadtail) | `head` / `tail` |
| [windate](https://github.com/fermat-tech/windate) | `date` |
| [winsort](https://github.com/fermat-tech/winsort) | `sort` |
| **winfile** | `file` |

## License

MIT — see [LICENSE](LICENSE).
