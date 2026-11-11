// Package runs keeps one folder per command a person ran, under one home
// ($AZHAQ_HOME, else ./.azhaq in the working directory): what was asked, when, how it ended, the
// command's own summary and where its workspace and files are. azhaq runs
// lists them and azhaq ui shows them.
package runs

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record is run.json.
type Record struct {
	ID        string          `json:"id"`
	Command   string          `json:"command"`
	Args      []string        `json:"args"` // secrets masked
	Target    string          `json:"target,omitempty"`
	Cwd       string          `json:"cwd,omitempty"`
	Version   string          `json:"version"`
	Pid       int             `json:"pid,omitempty"`
	Started   time.Time       `json:"started"`
	Ended     *time.Time      `json:"ended,omitempty"`
	Seconds   float64         `json:"seconds,omitempty"`
	Status    string          `json:"status"` // running, done
	Exit      *int            `json:"exit,omitempty"`
	Error     string          `json:"error,omitempty"`
	Workspace string          `json:"workspace,omitempty"`
	Wrote     []string        `json:"wrote,omitempty"`
	Summary   json.RawMessage `json:"summary,omitempty"` // the command's own summary, as -json prints it
}

const (
	StatusRunning = "running"
	StatusDone    = "done"
	recordFile    = "run.json"
	// WorkspaceFile is the workspace a run keeps when the person names none.
	WorkspaceFile = "workspace.db"
)

// Home is where runs are kept, and false when $AZHAQ_HOME turns it off.
// With none set it is .azhaq in the working directory, so an engagement's
// runs stay in its folder.
func Home() (string, bool) {
	v := os.Getenv("AZHAQ_HOME")
	switch strings.ToLower(v) {
	case "none", "off", "0", "false":
		return "", false
	case "":
		abs, err := filepath.Abs(".azhaq")
		if err != nil {
			return "", false
		}
		return abs, true
	}
	if abs, err := filepath.Abs(v); err == nil {
		v = abs
	}
	return v, true
}

// Dir is the folder that holds the runs of home.
func Dir(home string) string { return filepath.Join(home, "runs") }

// Run is the folder of the command running now.
type Run struct {
	Dir string
	mu  sync.Mutex
	rec Record
}

// Start makes the run's folder (0700) and writes run.json with status running.
func Start(home, command string, args []string, version string) (*Run, error) {
	now := time.Now()
	target := TargetOf(args)
	base := now.Format("20060102-150405") + "-" + command
	if s := Slug(target); s != "" {
		base += "-" + s
	}
	if err := os.MkdirAll(Dir(home), 0o700); err != nil {
		return nil, err
	}
	var dir, id string
	for i := range 100 {
		id = base
		if i > 0 {
			id = fmt.Sprintf("%s-%d", base, i+1)
		}
		dir = filepath.Join(Dir(home), id)
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return nil, err
		}
		dir = ""
	}
	if dir == "" {
		return nil, fmt.Errorf("runs: no free folder for %s", base)
	}
	cwd, _ := os.Getwd()
	r := &Run{Dir: dir, rec: Record{
		ID: id, Command: command, Args: Mask(args), Target: target, Cwd: cwd,
		Version: version, Pid: os.Getpid(), Started: now.UTC(), Status: StatusRunning,
	}}
	return r, r.save()
}

// SetSummary keeps the command's summary, its workspace and the files it wrote.
func (r *Run) SetSummary(raw []byte, workspace string, wrote []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rec.Summary = append(json.RawMessage(nil), raw...)
	if workspace != "" {
		r.rec.Workspace = absPath(workspace)
	}
	r.rec.Wrote = nil
	for _, w := range wrote {
		r.rec.Wrote = append(r.rec.Wrote, absPath(w))
	}
	_ = r.saveLocked()
}

// Finish records how the command ended.
func (r *Run) Finish(exit int, errText string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	r.rec.Ended = &now
	r.rec.Seconds = now.Sub(r.rec.Started).Seconds()
	r.rec.Status = StatusDone
	r.rec.Exit = &exit
	r.rec.Error = errText
	if r.rec.Workspace == "" {
		if p := filepath.Join(r.Dir, WorkspaceFile); exists(p) {
			r.rec.Workspace = p
		}
	}
	return r.saveLocked()
}

// Record is a copy of what run.json holds now.
func (r *Run) Record() Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rec
}

func (r *Run) save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.saveLocked()
}

func (r *Run) saveLocked() error {
	raw, err := json.MarshalIndent(r.rec, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(r.Dir, recordFile), raw)
}

// writeAtomic writes through a temporary file and a rename, so a reader
// never sees half a run.json.
func writeAtomic(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".run-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(append(raw, '\n'))
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		return errors.Join(werr, cerr)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// List reads every run of home, newest first. A folder without a
// readable run.json is not a run and is left out.
func List(home string) ([]Record, error) {
	ents, err := os.ReadDir(Dir(home))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		rec, err := Load(home, e.Name())
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Started.Equal(out[j].Started) {
			return out[i].Started.After(out[j].Started)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

var idRe = lazyre.New(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$`)

// ValidID says id names a run folder and nothing outside it.
func ValidID(id string) bool { return idRe.MatchString(id) && !strings.Contains(id, "..") }

// Load reads one run's record.
func Load(home, id string) (Record, error) {
	if !ValidID(id) {
		return Record{}, fmt.Errorf("not a run id: %q", id)
	}
	raw, err := os.ReadFile(filepath.Join(Dir(home), id, recordFile))
	if err != nil {
		return Record{}, err
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, fmt.Errorf("%s: %w", id, err)
	}
	rec.ID = id
	return rec, nil
}

// Remove deletes one run's folder: only a folder of home that holds a run.json.
func Remove(home, id string) error {
	if _, err := Load(home, id); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(Dir(home), id))
}

// Older lists the runs that started before cutoff.
func Older(home string, cutoff time.Time) ([]Record, error) {
	all, err := List(home)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, r := range all {
		if r.Started.Before(cutoff) {
			out = append(out, r)
		}
	}
	return out, nil
}

// targetFlags are the flags whose value names what a command was pointed at.
var targetFlags = map[string]bool{
	"url": true, "u": true, "domain": true, "d": true, "target": true, "host": true,
	"cidr": true, "asn": true, "list": true, "l": true, "program": true, "scope": true,
}

// TargetOf is what a command line was pointed at: the first target flag's
// value, else the first argument that is not a flag.
func TargetOf(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !targetFlags[name] {
			continue
		}
		if hasVal {
			return val
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	for i, a := range args {
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if i > 0 && strings.HasPrefix(args[i-1], "-") && !strings.Contains(args[i-1], "=") {
			continue // a flag's value
		}
		return a
	}
	return ""
}

var slugBad = lazyre.New(`[^a-z0-9.]+`)

// Slug is a target made safe for a folder name: a URL's host, lower case,
// at most 40 characters.
func Slug(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		t = u.Hostname()
	}
	t = strings.Trim(slugBad.ReplaceAllString(t, "-"), "-.")
	if len(t) > 40 {
		t = strings.Trim(t[:40], "-.")
	}
	return t
}

var secretName = lazyre.New(`(?i)pass|secret|token|key|cookie|auth|session|bearer|credential`)

// headerFlags carry a header line whose value is a secret when the header is.
var headerFlags = map[string]bool{"H": true, "header": true, "role": true}

const masked = "•••"

// Mask hides the secrets of a command line: the value of any flag named
// like a secret, the secret headers of -H/-header/-role, and a URL's password.
func Mask(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out); i++ {
		a := out[i]
		if a == "--" {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			out[i] = maskURL(a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch {
		case headerFlags[name]:
			if hasVal {
				out[i] = a[:len(a)-len(val)] + maskHeader(val)
			} else if i+1 < len(out) {
				out[i+1] = maskHeader(out[i+1])
				i++
			}
		case secretName.MatchString(name) && !isBoolish(val, hasVal, out, i):
			if hasVal {
				out[i] = a[:len(a)-len(val)] + masked
			} else if i+1 < len(out) && !strings.HasPrefix(out[i+1], "-") {
				out[i+1] = masked
				i++
			}
		}
	}
	return out
}

// isBoolish says a secret-named flag is a switch (-no-cookies), not a value.
func isBoolish(val string, hasVal bool, args []string, i int) bool {
	if hasVal {
		return val == "true" || val == "false"
	}
	return i+1 >= len(args) || strings.HasPrefix(args[i+1], "-")
}

// maskHeader keeps a header's name and hides its value when the name is a
// secret's; "role=Authorization: Bearer x" keeps "role=Authorization:".
func maskHeader(h string) string {
	name, _, ok := strings.Cut(h, ":")
	if !ok {
		return h
	}
	if secretName.MatchString(name) {
		return name + ": " + masked
	}
	return h
}

func maskURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), masked)
		return strings.Replace(u.String(), url.QueryEscape(masked), masked, 1)
	}
	return s
}

func absPath(p string) string {
	if p == "" {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// MaskJSON hides the values a JSON document keeps under a secret's name
// (cookie, authorization, token, …) and in header lines; invalid JSON is
// returned as it came.
func MaskJSON(raw []byte) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	out, err := json.Marshal(maskValue(v))
	if err != nil {
		return raw
	}
	return out
}

func maskValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if secretName.MatchString(k) && !isCountish(x) {
				t[k] = masked
				continue
			}
			t[k] = maskValue(x)
		}
	case []any:
		for i, x := range t {
			t[i] = maskValue(x)
		}
	case string:
		if name, _, ok := strings.Cut(t, ":"); ok && len(name) < 40 && !strings.ContainsAny(name, " /") && secretName.MatchString(name) {
			return maskHeader(t)
		}
	}
	return v
}

// isCountish keeps numbers and booleans under a secret-like name
// (cookies: 3, auth: true): they say what was there, not the secret.
func isCountish(v any) bool {
	switch v.(type) {
	case float64, bool, nil:
		return true
	}
	return false
}
