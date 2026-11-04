package verify

import (
	"bytes"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

// Each check sends exactly the bytes its table row names, once, and no
// credential: Redis INFO server, a MongoDB isMaster OP_MSG with only $db
// admin, memcached version.
func TestEachCheckSendsExactlyTheOneRequestItNames(t *testing.T) {
	isMaster := append([]byte{0x10}, "isMaster\x00\x01\x00\x00\x00"...) // an int32 element, no other field
	for _, c := range []struct {
		svc  advisory.Service
		want []byte
		resp []byte
	}{
		{advisory.Service{Service: "redis", Product: "Redis"}, []byte("INFO server\r\n"), []byte("$20\r\nredis_version:7.2.4\r\n\r\n")},
		{advisory.Service{Service: "memcached", Product: "memcached"}, []byte("version\r\n"), []byte("VERSION 1.6.21\r\n")},
		{advisory.Service{Service: "mongodb", Product: "MongoDB"}, mongoMsg(bsonDoc(isMaster, bsonStr("$db", "admin"))), mongoMsg(bsonDoc(bsonStr("version", "7.0.5"), bsonDouble("ok", 1)))},
	} {
		f := listen(t, func([]byte) []byte { return c.resp })
		runOne(t, c.svc, f)
		if len(f.sent) != 1 || !bytes.Equal(f.sent[0], c.want) {
			t.Errorf("%s: sent %q, want exactly %q once", c.svc.Service, f.sent, c.want)
		}
	}
}
