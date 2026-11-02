// Package contract holds the tests that fail whenever the azhaq binary breaks
// an invariant of its output: what a run sent (seen on the wire) is what its
// ledger lists and what its summary counts; the counts of a summary add up
// to the rows; the exit code follows the failures; the documentation keeps
// the promises it makes. The tests build the binary and run it as a user
// does, against labs on 127.0.0.1, so they do not depend on the command
// source and a change anywhere in it can break them.
package contract
