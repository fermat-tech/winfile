// text.go implements text-file encoding detection.
//
// [detectText] scans a byte sample and attempts to classify it as human-
// readable text, returning the character encoding and a short description
// compatible with GNU file output.
//
// Detection order:
//  1. UTF-32 BOM (FF FE 00 00 / 00 00 FE FF)
//  2. UTF-16 BOM (FF FE / FE FF)
//  3. UTF-8 BOM  (EF BB BF)
//  4. Heuristic scan over up to 8 KiB: count NUL bytes, non-UTF-8 sequences,
//     and control characters. Files with >1 % NUL or >5 % invalid bytes are
//     classified as binary (nil return). Otherwise the result is ASCII if no
//     high bytes appear, or UTF-8 otherwise.
//
// CRLF line endings are noted separately in the description when found, to
// match GNU file behaviour on Windows-style text files.
//
// [looksLikeJSON] is a lightweight check used by the text-refinement stage
// in detect.go to promote plain-text files to the JSON MIME type when the
// content starts with '{' or '['.
package main

import (
	"bytes"
	"unicode/utf8"
)

// textResult holds information about a text file's content and encoding.
type textResult struct {
	encoding string // e.g. "UTF-8", "UTF-16 (LE)", "ASCII"
	hasCR    bool   // CRLF line endings present
	desc     string // human description
	mime     string
}

// detectText tries to characterise buf as text.
// Returns nil if buf looks binary.
func detectText(buf []byte) *textResult {
	if len(buf) == 0 {
		return nil
	}

	// UTF-32 BOMs (must check before UTF-16)
	if len(buf) >= 4 {
		if buf[0] == 0xff && buf[1] == 0xfe && buf[2] == 0x00 && buf[3] == 0x00 {
			return &textResult{encoding: "UTF-32 (LE)", desc: "Unicode text, UTF-32, little-endian", mime: "text/plain"}
		}
		if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0xfe && buf[3] == 0xff {
			return &textResult{encoding: "UTF-32 (BE)", desc: "Unicode text, UTF-32, big-endian", mime: "text/plain"}
		}
	}

	// UTF-16 BOMs
	if len(buf) >= 2 {
		if buf[0] == 0xff && buf[1] == 0xfe {
			return &textResult{encoding: "UTF-16 (LE)", desc: "Unicode text, UTF-16, little-endian", mime: "text/plain"}
		}
		if buf[0] == 0xfe && buf[1] == 0xff {
			return &textResult{encoding: "UTF-16 (BE)", desc: "Unicode text, UTF-16, big-endian", mime: "text/plain"}
		}
	}

	// UTF-8 BOM
	if len(buf) >= 3 && buf[0] == 0xef && buf[1] == 0xbb && buf[2] == 0xbf {
		payload := buf[3:]
		hasCR := bytes.Contains(payload, []byte("\r\n"))
		return &textResult{encoding: "UTF-8 (with BOM)", hasCR: hasCR,
			desc: "Unicode text, UTF-8 (with BOM)", mime: "text/plain"}
	}

	// Heuristic: scan for non-text bytes
	// We allow: printable ASCII, tab, LF, CR, FF, BEL (common in logs), ESC (ANSI colour)
	// Treat NUL or high-ratio of non-UTF8 as binary.
	sample := buf
	if len(sample) > 8192 {
		sample = buf[:8192]
	}

	nullCount := 0
	nonUTF8 := 0
	highByte := 0
	hasCR := bytes.Contains(sample, []byte("\r\n"))

	i := 0
	for i < len(sample) {
		b := sample[i]
		if b == 0x00 {
			nullCount++
			i++
			continue
		}
		if b < 0x08 || (b >= 0x0e && b < 0x20 && b != 0x1b) {
			// control character (not tab/LF/CR/FF/BEL/ESC)
			nonUTF8++
			i++
			continue
		}
		if b >= 0x80 {
			highByte++
			r, size := utf8.DecodeRune(sample[i:])
			if r == utf8.RuneError && size == 1 {
				nonUTF8++
			}
			i += size
			continue
		}
		i++
	}

	total := len(sample)
	if nullCount > 0 && float64(nullCount)/float64(total) > 0.01 {
		return nil // binary
	}
	if float64(nonUTF8)/float64(total) > 0.05 {
		return nil // binary
	}

	if highByte == 0 {
		return &textResult{encoding: "us-ascii", hasCR: hasCR,
			desc: "ASCII text", mime: "text/plain"}
	}
	return &textResult{encoding: "utf-8", hasCR: hasCR,
		desc: "UTF-8 Unicode text", mime: "text/plain"}
}

// looksLikeJSON reports whether the sample appears to be JSON.
func looksLikeJSON(buf []byte) bool {
	s := bytes.TrimSpace(buf)
	if len(s) == 0 {
		return false
	}
	return (s[0] == '{' || s[0] == '[')
}
