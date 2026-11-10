package main

import "testing"

// A 2xx answer whose JSON says the request failed is a refusal, not an
// accepted write: VAmPI answers a register of a user that exists with 200
// and {"status":"fail","message":"User already exists. Please Log in."}.
func TestAWriteAnswered2xxWithAFailureIsNotAccepted(t *testing.T) {
	body := []byte(`{ "status": "fail", "message": "User already exists. Please Log in."}`)
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "text/html; charset=utf-8", ""} {
		a := answerOf(200, body, ct)
		if reads(a) || !refused(a) {
			t.Errorf("content type %q: reads %v, refused %v: a 2xx answer that says it failed is a refusal", ct, reads(a), refused(a))
		}
	}
}
