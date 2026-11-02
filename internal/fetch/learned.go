package fetch

import "sync"

var (
	learnedMu sync.Mutex
	learned   = map[string]string{}
)

// Learn keeps a short fact one task found for the others of the run, and
// for a resume of it: a collector that read something about an origin
// tells the tasks that would ask about the same.
func Learn(key, val string) {
	learnedMu.Lock()
	learned[key] = val
	learnedMu.Unlock()
	if Memos != nil {
		Memos.Remember("learned "+key, []byte(val))
	}
}

// Learned is what Learn kept under key, in this run or in the run a resume
// continues.
func Learned(key string) (string, bool) {
	learnedMu.Lock()
	v, ok := learned[key]
	learnedMu.Unlock()
	if ok || Memos == nil {
		return v, ok
	}
	if b, ok := Memos.Recall("learned " + key); ok && len(b) > 0 {
		return string(b), true
	}
	return "", false
}

func resetLearned() {
	learnedMu.Lock()
	learned = map[string]string{}
	learnedMu.Unlock()
}
