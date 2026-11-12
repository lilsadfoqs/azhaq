package engine

import (
	"encoding/json"
	"testing"
)

func TestResponseOfARowWithNoKeptAnswerIsNone(t *testing.T) {
	kept := json.RawMessage(`{"url":"http://a/","status":200,"response_headers":{"X":["1"]},"body_excerpt":"aGk=","body_length":2}`)
	if ev, ok := (MapEntry{answered: kept}).Response(); !ok || string(ev.Excerpt) != "hi" || ev.Headers["X"][0] != "1" {
		t.Errorf("a kept answer: %+v %v", ev, ok)
	}
	for name, m := range map[string]MapEntry{
		"a workspace from before the answer was kept": {answered: json.RawMessage(`{"url":"http://a/","status":200}`)},
		"a route nothing answered":                    {},
		"a folded row":                                {answered: kept, Count: 3},
	} {
		if _, ok := m.Response(); ok {
			t.Errorf("%s has an answer", name)
		}
	}
}
