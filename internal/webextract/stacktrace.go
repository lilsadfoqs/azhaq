package webextract

import (
	"bytes"
	"html"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// A Trace is a runtime's stack trace found in the body of an answer.
type Trace struct {
	Runtime   string `json:"runtime"`   // java, python, node, php, dotnet or ruby
	Exception string `json:"exception"` // the line that names the exception
	Frames    int    `json:"frames"`    // the frame lines of the runs of three or more
}

// TraceWindow is how much of a body is looked at.
const TraceWindow = 256 << 10

// MinFrames is the shortest run of frame lines that is a trace.
const MinFrames = 3

// A frame is a whole line, trimmed, shaped like one frame of a runtime's
// trace. gap is how many lines the runtime puts between two frames (the
// source line of a Python frame, its caret line).
var frameShapes = []struct {
	runtime string
	re      *lazyre.Regexp
	gap     int
}{
	{"java", lazyre.New(`^at\s+[\w$.<>/@\-]+\((?:[\w$.\-]+\.(?:java|kt|kts|scala|groovy|clj)(?::\d+)?|Native Method|Unknown Source)\)(?:\s*~?\[[^\]]*\])?$`), 0},
	{"python", lazyre.New(`^File "[^"]+", line \d+(?:, in .+)?$`), 2},
	{"node", lazyre.New(`^at\s+(?:async\s+)?(?:new\s+)?[^\s(][^()]*?\s+\(.+:\d+:\d+\)$|^at\s+(?:async\s+)?[^\s()]+:\d+:\d+$`), 0},
	{"php", lazyre.New(`^#\d+\s+(?:[^\s(][^()]*\(\d+\):\s+.+|\[internal function\]:\s+.+|\{main\})$`), 0},
	{"dotnet", lazyre.New(`^at\s+[\w$.<>+\x60\[\],]+\([^()]*\)\s+in\s+.+:line\s+\d+$`), 0},
	{"ruby", lazyre.New(`^(?:from\s+)?[^\s:]+\.rb:\d+:in\s+[\x60'][^']*'$`), 0},
}

var (
	tagBreak = lazyre.New(`(?i)<br\s*/?>|</(?:p|div|li|tr|td|pre|code|span|h[1-6])>`)
	anyTag   = lazyre.New(`<[^>]*>`)
	htmlLike = lazyre.New(`(?i)<(?:html|head|body|pre|br|div|p|span|code|li|ul|td|tr|table|h[1-6]|b|i|a)[\s/>]`)
	// What can be in a body that holds a frame: a cheap test before any
	// line is read.
	traceHints = [][]byte{
		[]byte(".java"), []byte("Native Method"), []byte("Unknown Source"), []byte("File \""), []byte(`File \"`), []byte("File &quot;"),
		[]byte(".js:"), []byte(".mjs:"), []byte(".cjs:"), []byte(".ts:"), []byte(".php("), []byte(":line "), []byte(".rb:"),
	}
)

// StackTrace says whether body holds a runtime's stack trace: three or more
// consecutive lines, each wholly shaped like a frame of the same runtime
// (`at pkg.Class.method(File.java:N)`, `File "x.py", line N, in f`,
// `at fn (file.js:L:C)`, `#N file.php(M)`, `at N.M() in F.cs:line N`,
// `file.rb:N:in 'm'`). Python's source and caret lines between its frames
// belong to the trace. A frame named in a sentence is not a line of its own,
// so prose about a trace holds none. HTML tags and entities and the \n of a
// JSON string are read as the text they stand for.
func StackTrace(body []byte) (Trace, bool) {
	if len(body) > TraceWindow {
		body = body[:TraceWindow]
	}
	hinted := false
	for _, h := range traceHints {
		if bytes.Contains(body, h) {
			hinted = true
			break
		}
	}
	if !hinted {
		return Trace{}, false
	}
	lines := traceLines(string(body))
	var best Trace
	for _, shape := range frameShapes {
		runs := frameRuns(lines, shape.re, shape.gap)
		frames := 0
		for _, r := range runs {
			frames += r.frames
		}
		if frames <= best.Frames || len(runs) == 0 {
			continue
		}
		best = Trace{Runtime: shape.runtime, Exception: exceptionOf(lines, runs[0], shape.runtime), Frames: frames}
	}
	return best, best.Frames > 0
}

// traceLines is body as text lines.
func traceLines(s string) []string {
	if htmlLike.MatchString(s) { // a <module> or <init> in plain text is not a tag
		s = anyTag.ReplaceAllString(tagBreak.ReplaceAllString(s, "\n"), "")
	}
	if strings.Contains(s, "&") {
		s = html.UnescapeString(s)
	}
	if t := strings.TrimSpace(s); len(t) > 0 && (t[0] == '{' || t[0] == '[') && strings.Contains(s, `\n`) {
		s = strings.NewReplacer(`\r\n`, "\n", `\n`, "\n", `\t`, "\t", `\"`, `"`, `\\`, `\`).Replace(s)
	}
	return strings.Split(strings.ReplaceAll(s, "\r", ""), "\n")
}

type frameRun struct{ start, last, frames int }

// frameRuns finds the runs of three or more frames, a frame at most gap
// non-blank lines after the one before it.
func frameRuns(lines []string, re *lazyre.Regexp, gap int) []frameRun {
	var runs []frameRun
	var cur *frameRun
	end := func() {
		if cur != nil && cur.frames >= MinFrames {
			runs = append(runs, *cur)
		}
		cur = nil
	}
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if len(t) <= 400 && t != "" && re.MatchString(t) {
			if cur != nil && i-cur.last-1 <= gap {
				cur.last, cur.frames = i, cur.frames+1
			} else {
				end()
				cur = &frameRun{start: i, last: i, frames: 1}
			}
			continue
		}
		if cur != nil && (t == "" || i-cur.last > gap) {
			end()
		}
	}
	end()
	return runs
}

var pyException = lazyre.New(`^[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Warning|Fault)\b|^[A-Za-z_][\w.]*: \S`)

// exceptionOf is the line that names the exception of a run: for Python the
// line after the frames, for the others the line before them.
func exceptionOf(lines []string, r frameRun, runtime string) string {
	pick := ""
	if runtime == "python" {
		for i := r.last + 1; i < len(lines) && i <= r.last+4; i++ {
			t := strings.TrimSpace(lines[i])
			if t == "" || strings.HasPrefix(lines[i], " ") || strings.HasPrefix(lines[i], "\t") || strings.HasPrefix(lines[i], " ") {
				continue
			}
			if pyException.MatchString(t) {
				pick = t
			}
			break
		}
		if pick == "" && r.start > 0 {
			if t := strings.TrimSpace(lines[r.start-1]); strings.HasPrefix(t, "Traceback") {
				pick = t
			}
		}
	} else {
		for i := r.start - 1; i >= 0 && i >= r.start-4; i-- {
			t := strings.TrimSpace(lines[i])
			if t == "" || strings.EqualFold(strings.TrimSuffix(t, ":"), "stack trace") {
				continue
			}
			pick = t
			break
		}
	}
	if pick == "" {
		pick = strings.TrimSpace(lines[r.start])
	}
	pick = strings.Join(strings.Fields(pick), " ")
	if len(pick) > 200 {
		pick = strings.ToValidUTF8(pick[:200], "") + "…"
	}
	return pick
}
