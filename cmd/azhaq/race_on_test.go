//go:build race

package main

// raceOn: the race detector slows every goroutine, so a wall-time bar
// needs room it does not need otherwise.
const raceOn = true
