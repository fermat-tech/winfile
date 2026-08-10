// magic.go implements magic-byte file-type detection.
//
// [detectMagic] reads up to 512+256 bytes from the start of a file and
// matches them against a table of well-known binary signatures ("magic
// numbers").  Each entry maps a byte pattern at a fixed offset to a human-
// readable description, a MIME type string, and a canonical extension.
//
// Format families covered: executables (PE, ELF, Mach-O), archives and
// compression (ZIP/OOXML, gzip, bzip2, XZ, zstd, LZ4, 7-Zip, RAR, tar,
// Cabinet), images (PNG, JPEG, GIF, BMP, TIFF, WebP, AVIF/HEIF, ICO, PSD,
// PPM/PGM/PBM), audio (WAV, FLAC, Ogg/Vorbis/Opus, MP3, MIDI, AIFF),
// video (AVI, MP4/MOV/M4V, MKV/WebM, FLV, ASF, MPEG), documents (PDF,
// PostScript, OLE2, RTF), databases (SQLite, Access), bytecode (Java .class,
// Python .pyc), fonts (TTF, OTF, WOFF, WOFF2), disk images (ISO 9660, MBR,
// VMDK, VHD/VHDX, QCOW2), and cryptographic containers (PEM, DER).
//
// Format-specific sub-detectors (peDetail, elfDetail, zipDetail, …) inspect
// additional header fields to produce richer descriptions—e.g. PE files
// report CPU architecture and EXE-vs-DLL, ZIP containers report OOXML
// sub-type (DOCX/XLSX/PPTX/JAR/EPUB), and Ogg streams report codec
// (Vorbis/Opus/Theora/Speex).
package main

import (
	"bytes"
	"encoding/binary"
)

// magicResult holds what we learned from magic-byte scanning.
type magicResult struct {
	desc     string
	mime     string
	ext      string
	encoding string // for text files
}

// detectMagic inspects raw bytes and returns the best match.
// It checks only the first ~262 bytes (standard magic window).
//
// path names the file the bytes came from, or is empty when they came from a
// stream that cannot be re-read (stdin, or a payload unwrapped from a
// compressed outer file). Sub-detectors that need to seek — currently only
// [elfDetail] — use it and fall back to a header-only reading without it.
func detectMagic(buf []byte, size int64, path string) *magicResult {
	if len(buf) == 0 || size == 0 {
		return &magicResult{desc: "empty", mime: "inode/x-empty", ext: "???"}
	}

	// --- Executables / object files ---
	if has(buf, 0, "MZ") {
		return peDetail(buf)
	}
	if has(buf, 0, "\x7fELF") {
		return elfDetail(buf, path)
	}
	if has(buf, 0, "\xfe\xed\xfa\xce") || has(buf, 0, "\xce\xfa\xed\xfe") ||
		has(buf, 0, "\xfe\xed\xfa\xcf") || has(buf, 0, "\xcf\xfa\xed\xfe") {
		return &magicResult{desc: "Mach-O executable", mime: "application/x-mach-binary", ext: "macho"}
	}

	// --- Archives & compression ---
	if has(buf, 0, "PK\x03\x04") {
		return zipDetail(buf)
	}
	if has(buf, 0, "PK\x05\x06") {
		return &magicResult{desc: "Zip archive (empty)", mime: "application/zip", ext: "zip"}
	}
	if has(buf, 0, "\x1f\x8b") {
		return &magicResult{desc: "gzip compressed data", mime: "application/gzip", ext: "gz"}
	}
	if has(buf, 0, "BZh") {
		return &magicResult{desc: "bzip2 compressed data", mime: "application/x-bzip2", ext: "bz2"}
	}
	if has(buf, 0, "\xfd7zXZ\x00") {
		return &magicResult{desc: "XZ compressed data", mime: "application/x-xz", ext: "xz"}
	}
	if has(buf, 0, "7z\xbc\xaf'\x1c") {
		return &magicResult{desc: "7-zip archive data", mime: "application/x-7z-compressed", ext: "7z"}
	}
	if has(buf, 0, "Rar!\x1a\x07\x00") || has(buf, 0, "Rar!\x1a\x07\x01\x00") {
		return &magicResult{desc: "RAR archive data", mime: "application/x-rar-compressed", ext: "rar"}
	}
	if has(buf, 0, "\x28\xb5\x2f\xfd") {
		return &magicResult{desc: "Zstandard compressed data", mime: "application/zstd", ext: "zst"}
	}
	if has(buf, 0, "\x04\x22\x4d\x18") || has(buf, 0, "\x02\x21\x4c\x18") {
		return &magicResult{desc: "LZ4 compressed data", mime: "application/x-lz4", ext: "lz4"}
	}
	if has(buf, 0, "LZIP") {
		return &magicResult{desc: "lzip compressed data", mime: "application/x-lzip", ext: "lz"}
	}
	if has(buf, 0, "\x5d\x00\x00") && len(buf) >= 13 {
		// LZMA alone (without XZ header)
		return &magicResult{desc: "LZMA compressed data", mime: "application/x-lzma", ext: "lzma"}
	}
	// TAR — POSIX "ustar" at offset 257
	if len(buf) >= 262 && (bytes.Equal(buf[257:262], []byte("ustar")) || bytes.Equal(buf[257:265], []byte("ustar  \x00"))) {
		return &magicResult{desc: "POSIX tar archive", mime: "application/x-tar", ext: "tar"}
	}
	// Old GNU tar magic also at 257
	if len(buf) >= 265 && bytes.Equal(buf[257:265], []byte("ustar  \x00")) {
		return &magicResult{desc: "GNU tar archive", mime: "application/x-tar", ext: "tar"}
	}
	if has(buf, 0, "SZDD") {
		return &magicResult{desc: "MS-DOS compressed file (SZDD)", mime: "application/x-compress", ext: "???"}
	}
	if has(buf, 0, "\x1f\x9d") {
		return &magicResult{desc: "compress'd data", mime: "application/x-compress", ext: "Z"}
	}
	if has(buf, 0, "\x1f\xa0") {
		return &magicResult{desc: "compress'd data (LZH)", mime: "application/x-lzh-compressed", ext: "lzh"}
	}
	if has(buf, 0, "MSCF") {
		return &magicResult{desc: "Microsoft Cabinet archive data", mime: "application/vnd.ms-cab-compressed", ext: "cab"}
	}
	if has(buf, 0, "ISc(") {
		return &magicResult{desc: "InstallShield archive", mime: "application/x-installshield", ext: "cab"}
	}
	if has(buf, 0, "XPCK") || has(buf, 0, "XPK!") {
		return &magicResult{desc: "XPK compressed data", mime: "application/x-xpk", ext: "xpk"}
	}
	if has(buf, 0, "!<arch>\n") {
		return &magicResult{desc: "ar archive (static library)", mime: "application/x-archive", ext: "a"}
	}

	// --- Images ---
	if has(buf, 0, "\x89PNG\r\n\x1a\n") {
		return &magicResult{desc: "PNG image data", mime: "image/png", ext: "png"}
	}
	if has(buf, 0, "\xff\xd8\xff") {
		return jpegDetail(buf)
	}
	if has(buf, 0, "GIF87a") {
		return &magicResult{desc: "GIF image data, version 87a", mime: "image/gif", ext: "gif"}
	}
	if has(buf, 0, "GIF89a") {
		return &magicResult{desc: "GIF image data, version 89a", mime: "image/gif", ext: "gif"}
	}
	if has(buf, 0, "BM") && len(buf) >= 6 {
		return &magicResult{desc: "PC bitmap", mime: "image/bmp", ext: "bmp"}
	}
	if has(buf, 0, "II\x2a\x00") {
		return &magicResult{desc: "TIFF image data, little-endian", mime: "image/tiff", ext: "tiff"}
	}
	if has(buf, 0, "MM\x00\x2a") {
		return &magicResult{desc: "TIFF image data, big-endian", mime: "image/tiff", ext: "tiff"}
	}
	if has(buf, 0, "RIFF") && len(buf) >= 12 && has(buf, 8, "WEBP") {
		return &magicResult{desc: "RIFF (little-endian) data, Web/P image", mime: "image/webp", ext: "webp"}
	}
	if has(buf, 0, "\x00\x00\x01\x00") {
		return &magicResult{desc: "MS Windows icon resource", mime: "image/x-icon", ext: "ico"}
	}
	if has(buf, 0, "\x00\x00\x02\x00") {
		return &magicResult{desc: "MS Windows cursor resource", mime: "image/x-win-bitmap", ext: "cur"}
	}
	// JPEG 2000
	if has(buf, 0, "\x00\x00\x00\x0cjP  \r\n\x87\n") {
		return &magicResult{desc: "JPEG 2000 image", mime: "image/jp2", ext: "jp2"}
	}
	// AVIF / HEIF (ftyp box)
	if len(buf) >= 12 && has(buf, 4, "ftyp") {
		brand := string(buf[8:12])
		switch brand {
		case "avif", "avis":
			return &magicResult{desc: "AVIF image data", mime: "image/avif", ext: "avif"}
		case "heic", "heix", "hevc":
			return &magicResult{desc: "HEIF image data", mime: "image/heif", ext: "heic"}
		case "mif1", "msf1":
			return &magicResult{desc: "HEIF image data", mime: "image/heif", ext: "heif"}
		}
	}
	if has(buf, 0, "8BPS") {
		return &magicResult{desc: "Adobe Photoshop Image", mime: "image/vnd.adobe.photoshop", ext: "psd"}
	}
	if has(buf, 0, "GIMP") {
		return &magicResult{desc: "GIMP XCF image data", mime: "image/x-xcf", ext: "xcf"}
	}
	// TGA — no reliable magic, skip
	// PPM/PGM/PBM
	if len(buf) >= 2 && buf[0] == 'P' && buf[1] >= '1' && buf[1] <= '6' {
		names := map[byte]string{'1': "PBM", '2': "PGM", '3': "PPM", '4': "PBM", '5': "PGM", '6': "PPM"}
		return &magicResult{desc: "Netpbm " + names[buf[1]] + " image data", mime: "image/x-portable-pixmap", ext: "pnm"}
	}

	// --- Audio ---
	if has(buf, 0, "RIFF") && len(buf) >= 12 && has(buf, 8, "WAVE") {
		return &magicResult{desc: "RIFF (little-endian) data, WAVE audio", mime: "audio/x-wav", ext: "wav"}
	}
	if has(buf, 0, "fLaC") {
		return &magicResult{desc: "FLAC audio bitstream data", mime: "audio/flac", ext: "flac"}
	}
	if has(buf, 0, "OggS") {
		return oggDetail(buf)
	}
	if has(buf, 0, "ID3") || (len(buf) >= 2 && buf[0] == 0xff && buf[1]&0xe0 == 0xe0) {
		return &magicResult{desc: "MPEG ADTS, layer III, audio", mime: "audio/mpeg", ext: "mp3"}
	}
	if has(buf, 0, "MAC ") {
		return &magicResult{desc: "Monkey's Audio compressed format", mime: "audio/x-ape", ext: "ape"}
	}
	if has(buf, 0, "wvpk") {
		return &magicResult{desc: "WavPack audio", mime: "audio/x-wavpack", ext: "wv"}
	}
	if has(buf, 0, "FORM") && len(buf) >= 12 && has(buf, 8, "AIFF") {
		return &magicResult{desc: "IFF data, AIFF audio", mime: "audio/aiff", ext: "aif"}
	}
	if has(buf, 0, ".snd") {
		return &magicResult{desc: "Sun/NeXT audio data", mime: "audio/basic", ext: "au"}
	}
	if has(buf, 0, "RIFF") && len(buf) >= 12 && has(buf, 8, "MIDI") {
		return &magicResult{desc: "RIFF MIDI data", mime: "audio/midi", ext: "rmi"}
	}
	if has(buf, 0, "MThd") {
		return &magicResult{desc: "Standard MIDI data", mime: "audio/midi", ext: "mid"}
	}

	// --- Video ---
	if has(buf, 0, "RIFF") && len(buf) >= 12 && has(buf, 8, "AVI ") {
		return &magicResult{desc: "RIFF (little-endian) data, AVI", mime: "video/x-msvideo", ext: "avi"}
	}
	if len(buf) >= 12 && has(buf, 4, "ftyp") {
		brand := string(buf[8:12])
		switch brand {
		case "mp41", "mp42", "isom", "iso2":
			return &magicResult{desc: "ISO Media, MPEG v4 system", mime: "video/mp4", ext: "mp4"}
		case "M4V ", "M4VH", "M4VP":
			return &magicResult{desc: "ISO Media, MPEG v4 (M4V)", mime: "video/x-m4v", ext: "m4v"}
		case "M4A ", "M4B ":
			return &magicResult{desc: "ISO Media, MPEG v4 audio (M4A)", mime: "audio/mp4", ext: "m4a"}
		case "qt  ":
			return &magicResult{desc: "Apple QuickTime movie", mime: "video/quicktime", ext: "mov"}
		case "3gp5", "3gp4":
			return &magicResult{desc: "3GPP Media", mime: "video/3gpp", ext: "3gp"}
		case "f4v ":
			return &magicResult{desc: "Adobe Flash Video", mime: "video/mp4", ext: "f4v"}
		}
	}
	if has(buf, 0, "\x1a\x45\xdf\xa3") {
		return mkvDetail(buf)
	}
	if has(buf, 0, "FLV\x01") {
		return &magicResult{desc: "Macromedia Flash Video", mime: "video/x-flv", ext: "flv"}
	}
	if has(buf, 0, "\x30\x26\xb2\x75\x8e\x66\xcf\x11") {
		return &magicResult{desc: "Microsoft ASF", mime: "video/x-ms-asf", ext: "asf"}
	}
	if has(buf, 0, "\x00\x00\x01\xb3") || has(buf, 0, "\x00\x00\x01\xba") {
		return &magicResult{desc: "MPEG video stream data", mime: "video/mpeg", ext: "mpg"}
	}
	if has(buf, 0, "RIFF") && len(buf) >= 12 && has(buf, 8, "CDXA") {
		return &magicResult{desc: "RIFF (little-endian) data, Video CD", mime: "video/mpeg", ext: "mpg"}
	}
	if has(buf, 0, "\x00\x00\x00\x01") && len(buf) >= 5 && (buf[4]&0x1f == 0x09) {
		return &magicResult{desc: "H.264 video stream", mime: "video/h264", ext: "h264"}
	}

	// --- Documents ---
	if has(buf, 0, "%PDF-") {
		v := ""
		if len(buf) >= 8 {
			v = string(buf[5:8])
		}
		return &magicResult{desc: "PDF document, version " + v, mime: "application/pdf", ext: "pdf"}
	}
	if has(buf, 0, "%!PS-Adobe-") {
		return &magicResult{desc: "PostScript document text", mime: "application/postscript", ext: "ps"}
	}
	if has(buf, 0, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
		return oleDetail(buf)
	}
	if has(buf, 0, "{\\rtf") {
		return &magicResult{desc: "Rich Text Format data", mime: "text/rtf", ext: "rtf"}
	}
	if has(buf, 0, "\x09\x04\x06\x00\x00\x00\x10\x00") {
		return &magicResult{desc: "Lotus 1-2-3 spreadsheet", mime: "application/x-lotus", ext: "wk4"}
	}
	// EPUB (also ZIP; checked after generic ZIP)
	if has(buf, 0, "PK\x03\x04") {
		// already handled by zipDetail
	}

	// --- Fonts ---
	if has(buf, 0, "\x00\x01\x00\x00\x00") {
		return &magicResult{desc: "TrueType Font data", mime: "font/ttf", ext: "ttf"}
	}
	if has(buf, 0, "OTTO") {
		return &magicResult{desc: "OpenType Font data (CFF)", mime: "font/otf", ext: "otf"}
	}
	if has(buf, 0, "true") {
		return &magicResult{desc: "TrueType Font data (Apple)", mime: "font/ttf", ext: "ttf"}
	}
	if has(buf, 0, "wOFF") {
		return &magicResult{desc: "Web Open Font Format", mime: "font/woff", ext: "woff"}
	}
	if has(buf, 0, "wOF2") {
		return &magicResult{desc: "Web Open Font Format 2", mime: "font/woff2", ext: "woff2"}
	}

	// --- Crypto / certs ---
	if hasASCII(buf, "-----BEGIN CERTIFICATE-----") {
		return &magicResult{desc: "PEM certificate", mime: "application/x-pem-file", ext: "pem"}
	}
	if hasASCII(buf, "-----BEGIN") {
		return &magicResult{desc: "PEM data", mime: "application/x-pem-file", ext: "pem"}
	}
	if has(buf, 0, "\x30\x82") {
		return &magicResult{desc: "DER Encoded Certificate", mime: "application/x-x509-ca-cert", ext: "der"}
	}
	if has(buf, 0, "\x30\x80") || (len(buf) >= 2 && buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84) {
		return &magicResult{desc: "DER Encoded data", mime: "application/x-x509-ca-cert", ext: "der"}
	}

	// --- Database ---
	if has(buf, 0, "SQLite format 3\x00") {
		return &magicResult{desc: "SQLite 3.x database", mime: "application/x-sqlite3", ext: "db"}
	}
	if has(buf, 0, "\x00\x00\x00\x20Ore") || has(buf, 0, "\x00\x06\x15\x61\x00\x00") {
		return &magicResult{desc: "Microsoft Access database", mime: "application/x-msaccess", ext: "mdb"}
	}

	// --- Compiled code / bytecode ---
	if has(buf, 0, "\xca\xfe\xba\xbe") {
		return &magicResult{desc: "Java class data", mime: "application/x-java-applet", ext: "class"}
	}
	if has(buf, 0, "\xce\xfa\xed\xfe") {
		return &magicResult{desc: "Mach-O binary (32-bit, BE)", mime: "application/x-mach-binary", ext: "macho"}
	}
	// Python bytecode
	if has(buf, 0, "\x16\x0d\x0d\x0a") || has(buf, 0, "\x33\x0d\x0d\x0a") || has(buf, 0, "\x42\x0d\x0d\x0a") {
		return &magicResult{desc: "Python bytecode", mime: "application/x-python-code", ext: "pyc"}
	}

	// --- Disk images ---
	if has(buf, 0, "MZ") {
		// already handled above
	}
	if has(buf, 0, "\x43\x44\x30\x30\x31") {
		return &magicResult{desc: "ISO 9660 CD-ROM filesystem data", mime: "application/x-iso9660-image", ext: "iso"}
	}
	if len(buf) >= 512 && has(buf, 510, "\x55\xaa") {
		return &magicResult{desc: "DOS/MBR boot sector", mime: "application/octet-stream", ext: "img"}
	}
	// VMDK
	if has(buf, 0, "KDMV") {
		return &magicResult{desc: "VMware disk image", mime: "application/x-vmdk", ext: "vmdk"}
	}
	// VHD / VHDX
	if has(buf, 0, "vhdxfile") {
		return &magicResult{desc: "Microsoft VHDX disk image", mime: "application/x-vhd", ext: "vhdx"}
	}
	if has(buf, 0, "conectix") {
		return &magicResult{desc: "VirtualPC / Virtual Server disk image", mime: "application/x-vhd", ext: "vhd"}
	}
	// QCOW2
	if has(buf, 0, "QFI\xfb") {
		return &magicResult{desc: "QEMU QCOW2 Image", mime: "application/x-qcow2", ext: "qcow2"}
	}

	// --- Scripting / markup (text-based, check early prefixes) ---
	if hasASCII(buf, "<?xml") || hasASCII(buf, "<?XML") {
		return &magicResult{desc: "XML document text", mime: "application/xml", ext: "xml"}
	}
	if hasASCII(buf, "<html") || hasASCII(buf, "<HTML") || hasASCII(buf, "<!DOCTYPE html") || hasASCII(buf, "<!DOCTYPE HTML") {
		return &magicResult{desc: "HTML document text", mime: "text/html", ext: "html"}
	}
	if hasASCII(buf, "#!/") || hasASCII(buf, "#! /") {
		return shebangDetail(buf)
	}

	return nil
}

// --- helpers ---

func has(buf []byte, off int, magic string) bool {
	m := []byte(magic)
	if off+len(m) > len(buf) {
		return false
	}
	return bytes.Equal(buf[off:off+len(m)], m)
}

func hasASCII(buf []byte, s string) bool {
	return bytes.Contains(buf[:min(len(buf), 512)], []byte(s))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- format-specific detectors ---

func peDetail(buf []byte) *magicResult {
	// Follow the PE offset at 0x3c
	if len(buf) < 0x40 {
		return &magicResult{desc: "MS-DOS executable", mime: "application/x-dosexec", ext: "exe"}
	}
	peOff := int(binary.LittleEndian.Uint32(buf[0x3c:]))
	if peOff+6 > len(buf) {
		return &magicResult{desc: "MS-DOS executable", mime: "application/x-dosexec", ext: "exe"}
	}
	if !has(buf, peOff, "PE\x00\x00") {
		return &magicResult{desc: "MS-DOS executable", mime: "application/x-dosexec", ext: "exe"}
	}
	machine := binary.LittleEndian.Uint16(buf[peOff+4:])
	var arch string
	switch machine {
	case 0x14c:
		arch = "Intel 80386"
	case 0x8664:
		arch = "x86-64"
	case 0xaa64:
		arch = "ARM aarch64"
	case 0x1c0, 0x1c4:
		arch = "ARM"
	default:
		arch = "unknown"
	}
	// Check optional header magic for DLL vs EXE
	if peOff+24+2 > len(buf) {
		return &magicResult{desc: "PE32 executable (" + arch + ")", mime: "application/x-dosexec", ext: "exe"}
	}
	charOff := peOff + 22
	var kind string
	if charOff+2 <= len(buf) {
		chars := binary.LittleEndian.Uint16(buf[charOff:])
		if chars&0x2000 != 0 {
			kind = "DLL"
		} else if chars&0x0002 != 0 {
			kind = "executable"
		} else {
			kind = "object"
		}
	}
	optMagic := uint16(0)
	if peOff+24+2 <= len(buf) {
		optMagic = binary.LittleEndian.Uint16(buf[peOff+24:])
	}
	bits := "PE32"
	if optMagic == 0x20b {
		bits = "PE32+"
	}
	ext := "exe"
	if kind == "DLL" {
		ext = "dll"
	}
	return &magicResult{
		desc: bits + " " + kind + " (" + arch + "), for MS Windows",
		mime: "application/x-dosexec",
		ext:  ext,
	}
}

func zipDetail(buf []byte) *magicResult {
	// Peek at first local file name to detect docx/xlsx/odt/jar/apk/epub
	if len(buf) >= 34 {
		fnLen := int(binary.LittleEndian.Uint16(buf[26:]))
		extraLen := int(binary.LittleEndian.Uint16(buf[28:]))
		if 30+fnLen <= len(buf) {
			firstName := string(buf[30 : 30+fnLen])
			switch firstName {
			case "word/":
				return &magicResult{desc: "Microsoft Word 2007+", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ext: "docx"}
			case "xl/":
				return &magicResult{desc: "Microsoft Excel 2007+", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ext: "xlsx"}
			case "ppt/":
				return &magicResult{desc: "Microsoft PowerPoint 2007+", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", ext: "pptx"}
			case "META-INF/":
				// Could be JAR, APK, or ODF
				_ = extraLen
				return &magicResult{desc: "Java archive (jar/apk)", mime: "application/java-archive", ext: "jar"}
			case "mimetype":
				return &magicResult{desc: "OpenDocument/EPUB container", mime: "application/epub+zip", ext: "epub"}
			}
		}
	}
	return &magicResult{desc: "Zip archive data", mime: "application/zip", ext: "zip"}
}

func jpegDetail(buf []byte) *magicResult {
	if len(buf) >= 12 && has(buf, 6, "JFIF\x00") {
		return &magicResult{desc: "JPEG image data, JFIF standard", mime: "image/jpeg", ext: "jpg"}
	}
	if len(buf) >= 12 && has(buf, 6, "Exif\x00") {
		return &magicResult{desc: "JPEG image data, Exif standard", mime: "image/jpeg", ext: "jpg"}
	}
	return &magicResult{desc: "JPEG image data", mime: "image/jpeg", ext: "jpg"}
}

func oggDetail(buf []byte) *magicResult {
	// Ogg page header: capture_pattern at 0, type at 5, granule at 6-13, serial at 14-17, seq at 18-21
	// Codec ID is in the first packet starting at byte 28 typically
	if len(buf) >= 35 {
		if has(buf, 29, "\x01vorbis") {
			return &magicResult{desc: "Ogg data, Vorbis audio", mime: "audio/ogg", ext: "ogg"}
		}
		if has(buf, 28, "OpusHead") {
			return &magicResult{desc: "Ogg data, Opus audio", mime: "audio/ogg", ext: "opus"}
		}
		if has(buf, 28, "\x80theora") {
			return &magicResult{desc: "Ogg data, Theora video", mime: "video/ogg", ext: "ogv"}
		}
		if has(buf, 28, "Speex  ") {
			return &magicResult{desc: "Ogg data, Speex audio", mime: "audio/ogg", ext: "spx"}
		}
		if has(buf, 28, "\x01audio") {
			return &magicResult{desc: "Ogg data, FLAC audio", mime: "audio/ogg", ext: "oga"}
		}
	}
	return &magicResult{desc: "Ogg data", mime: "application/ogg", ext: "ogx"}
}

func mkvDetail(buf []byte) *magicResult {
	// EBML: look for docType string in first 64 bytes
	if bytes.Contains(buf[:min(len(buf), 64)], []byte("webm")) {
		return &magicResult{desc: "WebM video", mime: "video/webm", ext: "webm"}
	}
	return &magicResult{desc: "Matroska media container", mime: "video/x-matroska", ext: "mkv"}
}

func oleDetail(buf []byte) *magicResult {
	// OLE2 compound document: used by DOC, XLS, PPT, MSG, etc.
	// We can't reliably distinguish without reading the directory stream, so use a generic description.
	return &magicResult{desc: "Composite Document File V2 (Microsoft Office)", mime: "application/x-ole-storage", ext: "ole"}
}

func shebangDetail(buf []byte) *magicResult {
	nl := bytes.IndexByte(buf, '\n')
	if nl < 0 {
		nl = len(buf)
	}
	line := string(buf[:nl])
	for _, kv := range []struct{ kw, desc, mime, ext string }{
		{"python3", "Python script", "text/x-python", "py"},
		{"python2", "Python script", "text/x-python", "py"},
		{"python", "Python script", "text/x-python", "py"},
		{"bash", "Bourne-Again shell script", "text/x-shellscript", "sh"},
		{"sh", "POSIX shell script", "text/x-shellscript", "sh"},
		{"zsh", "Zsh script", "text/x-shellscript", "sh"},
		{"fish", "Fish shell script", "text/x-shellscript", "fish"},
		{"perl", "Perl script", "text/x-perl", "pl"},
		{"ruby", "Ruby script", "text/x-ruby", "rb"},
		{"node", "Node.js script", "application/javascript", "js"},
		{"env node", "Node.js script", "application/javascript", "js"},
		{"env python", "Python script", "text/x-python", "py"},
		{"php", "PHP script", "text/x-php", "php"},
		{"lua", "Lua script", "text/x-lua", "lua"},
		{"awk", "awk script", "text/x-awk", "awk"},
		{"tclsh", "Tcl script", "text/x-tcl", "tcl"},
	} {
		if bytes.Contains([]byte(line), []byte(kv.kw)) {
			return &magicResult{desc: kv.desc + " text executable", mime: kv.mime, ext: kv.ext}
		}
	}
	return &magicResult{desc: "script text executable", mime: "text/x-shellscript", ext: "sh"}
}
