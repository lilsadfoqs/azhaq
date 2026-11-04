package main

import (
	"os"
	"path/filepath"
)

// historyDirHelp says where the name history is kept when no one names a place.
const historyDirHelp = "$AZHAQ_DATA_DIR if set, else azhaq-data/ beside -db (the current directory for a run with a temporary database)"

// historyDirOf is the directory of the name history: -history-dir, else
// $AZHAQ_DATA_DIR, else azhaq-data in the folder the run works in, beside its
// database (the current directory when the database is temporary). A history
// shared between workspaces is one the user named.
func historyDirOf(flag, db string, temporary bool) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv("AZHAQ_DATA_DIR"); v != "" {
		return v
	}
	if temporary || db == "" {
		return "azhaq-data"
	}
	return filepath.Join(filepath.Dir(db), "azhaq-data")
}
