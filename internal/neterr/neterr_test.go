package neterr

import (
	"crypto/tls"
	"errors"
	"fmt"
	"testing"
)

func TestNotHTTPAndNotTLS(t *testing.T) {
	for _, tc := range []struct {
		err             error
		notHTTP, notTLS bool
	}{
		{errors.New(`Get "http://h:21/": net/http: HTTP/1.x transport connection broken: malformed HTTP status code "FTP"`), true, true},
		{errors.New(`Get "http://h:22/": malformed HTTP response "SSH-2.0-OpenSSH_9.0"`), true, true},
		{errors.New(`Get "http://h:22/": readLoopPeekFailLocked: %!w(<nil>)`), true, true},
		{errors.New(`Get "http://h:8443/": malformed HTTP response "\x15\x03\x01\x00\x02\x02\x16"`), true, false},
		{fmt.Errorf("Get: %w", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), true, true},
		{errors.New("Get: EOF"), false, false},
		{errors.New("read: connection reset by peer"), false, false},
		{errors.New("context deadline exceeded"), false, false},
		{nil, false, false},
	} {
		if got := NotHTTP(tc.err); got != tc.notHTTP {
			t.Errorf("NotHTTP(%v) = %v", tc.err, got)
		}
		if got := NotTLS(tc.err); got != tc.notTLS {
			t.Errorf("NotTLS(%v) = %v", tc.err, got)
		}
	}
}
