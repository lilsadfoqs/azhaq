#!/bin/bash
# toolfree.sh SEED OUT AZHAQ [PORT]: one sample of the agent-free arms. Generates the app for SEED,
# checks that every flaw of its key reproduces, captures the journey, runs B1 (azhaq roles) on the
# app as the capture left it, restarts the app fresh and runs B2 (the Autorize logic), grades both.
# OUT gets key.json, app.json, vars.json, har/, b1/ and b2/ (each with grade.json): all of it is
# private and goes out encrypted. stdout holds counts only.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
seed=${1:?usage: toolfree.sh SEED OUT AZHAQ [PORT]}
out=${2:?}
azhaq=${3:?}
port=${4:-8190}
. "$here/appctl.sh"
url=http://127.0.0.1:$port
mkdir -p "$out"
out=$(cd "$out" && pwd)
count=$out/.count
trap 'app_stop "$port" || true' EXIT

python3 "$here/gen.py" "$seed" --out "$out"
app_start "$out" "$port" "$count"
python3 "$here/selfcheck.py" "$out" "$url"
app_stop "$port"

app_start "$out" "$port" "$count"
python3 "$here/journey.py" "$out" "$url" --out "$out/har"

# B1: the app as the capture left it
mkdir -p "$out/b1"
python3 "$here/b1.py" --azhaq "$azhaq" --url "$url" --har-dir "$out/har" --out "$out/b1" --count-file "$count"
python3 "$here/grade.py" "$out/key.json" "$out/b1" --arm b1
app_stop "$port"

# B2: a fresh app, the capture replayed in its order
app_start "$out" "$port" "$count"
mkdir -p "$out/b2"
python3 "$here/autorize.py" --url "$url" --sessions "$out/har/sessions.json" --har "$out/har/admin.har=alice" \
  --har "$out/har/alice.har=bob" --out "$out/b2/b2.jsonl" --meta "$out/b2/meta.json" --count-file "$count"
python3 "$here/grade.py" "$out/key.json" "$out/b2" --arm b2
rm -rf "$out/b1/.azhaq" "$out/.count"
