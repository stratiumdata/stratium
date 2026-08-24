package agent

import (
	"io"
	"os"
)

// ColourEnabled reports whether ANSI colour escapes should be written to w:
// never when NO_COLOR is set to any non-empty value (https://no-color.org),
// and never when w is not a terminal -- this suite's transcripts get pasted
// into READMEs and piped into report files, and escape codes there are noise,
// not colour. A w that is not an *os.File (a bytes.Buffer in a test, say) is
// treated the same as a non-terminal: colour off, the fail-closed-to-plain-
// text default.
func ColourEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
