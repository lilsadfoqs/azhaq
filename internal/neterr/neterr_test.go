package neterr

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"syscall"
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

func TestClosedAtOnce(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf(`Get "http://h:1099/": %w`, io.EOF), true},
		{errors.New(`Get "http://h:1099/": read tcp 1.2.3.4:5->6.7.8.9:1099: read: connection reset by peer`), true},
		{fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{fmt.Errorf("dial: %w", syscall.ECONNREFUSED), false},
		{context.DeadlineExceeded, false},
		{fmt.Errorf("Get: %w", tls.AlertError(40)), false},
		{errors.New("tls: handshake failure"), false},
		{nil, false},
	} {
		if got := ClosedAtOnce(tc.err); got != tc.want {
			t.Errorf("ClosedAtOnce(%v) = %v", tc.err, got)
		}
	}
}
