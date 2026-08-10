# winfile

`winfile` is a Windows port of the classic Unix [`file`](https://www.darwinsys.com/file/) command.
It identifies the type of one or more files by examining their **content** (magic bytes, encoding heuristics, and structural markers) rather than relying on file extensions alone. Output is compatible with GNU `file` so it drops into existing scripts and pipelines unchanged.

```
winfile [OPTION...] FILE...
```

## Installation

**Pre-built binary** — grab the one for your platform from the [Releases](https://github.com/fermat-tech/winfile/releases) page and put it on your `PATH`. The binaries are self-contained, with nothing to extract or install.

| Asset | Platform |
|---|---|
| `winfile_windows_amd64.exe` | Windows, x86-64 |
| `winfile_windows_arm64.exe` | Windows, ARM64 |
| `winfile_linux_amd64` | Linux, x86-64 |
| `winfile_linux_arm64` | Linux, ARM64 |

Rename it to `winfile.exe` (or `winfile`) once it is on your `PATH`: the binary
takes its name from argv[0], so whatever you call it is what appears in its
messages. On Linux, `chmod +x` it first.

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
| Executables | PE (EXE/DLL/OBJ), ELF ([full detail](#elf-detail)), Mach-O |
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

<a name="elf-detail"></a>
### ELF detail

ELF images are described the way GNU `file` describes them, not just by class
and object type:

```
$ winfile -b /bin/ls
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=897a5bd7…, for GNU/Linux 3.2.0, stripped

$ winfile -b core.1234
ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from '/usr/bin/crasher', real uid: 1000, effective uid: 1000, real gid: 1000, effective gid: 1000, execfn: '/usr/bin/crasher', platform: 'x86_64'
```

Reported: object type, machine, ELF version and OS/ABI; linkage
(`dynamically` / `statically` / `static-pie` linked); the `PT_INTERP`
interpreter path; GNU and Go build IDs; the `.note.ABI-tag` target OS and
version; presence of `.debug_info`; stripped state; and, for core dumps, the
dumping process, its real/effective uid and gid, `execfn` and `platform`.

Two things are inferred rather than read from a field, matching what GNU
`file` does:

- **`pie executable` vs `shared object`.** Both are `ET_DYN`. An image whose
  `.dynamic` section carries `DT_FLAGS_1` with `DF_1_PIE` is reported as a PIE
  executable; otherwise it is a shared library.
- **`static-pie linked`.** An image with a `.dynamic` section but no
  interpreter and no `DT_NEEDED` entries has nothing to bind at run time.

Verified against GNU `file` 5.41 over a 1348-file corpus (`/bin`, shared
libraries, relocatable objects, static and PIE executables, Go binaries and a
core dump): no differences in the ELF description.

#### Known differences from GNU file

| Case | Behavior |
|------|----------|
| Uncommon `e_machine` values | Only x86-64, i386, ARM, AArch64, RISC-V and 64-bit PowerPC are named (with their flag-derived ABI suffixes). Other machines are left unnamed rather than guessed at, so the description omits the architecture instead of printing `*unknown arch 0x…*`. |
| Non-seekable input | Reading a compressed payload with `-z` yields the header-only description — class, byte order, type, machine, version, OS/ABI. GNU `file` behaves the same way here. |
| Truncated or malformed images | If the ELF structure will not parse, winfile reports the header-only description. GNU `file` reports as much as it decoded plus an error fragment such as `missing section headers at 14408`. |
| `e_version` other than 1 | The header-only description is used, because Go's `debug/elf` rejects the file. Real toolchains always emit 1. |
| NetBSD core dumps | Reported as `NetBSD-style`; the `NT_NETBSD_CORE_PROCINFO` fields (pid, uid, gid, signal) are not decoded. |
| `setuid` / `setgid` prefix | Not reported. This comes from the file's permission bits, not from the ELF image, and Windows has no such bits. |

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
