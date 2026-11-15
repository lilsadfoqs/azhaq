#!/bin/bash
# stack.sh OUT EXPORT DNS: the usual tools' answer to "what product and
# version is this service", asked of the services azhaq found (EXPORT, its
# workspace export), so ident.py compares the naming, not the finding.
#   nmap -sV    each address's open TCP ports (the service and version probes)
#   httpx -td   each web root, with title and Server header (wappalyzer's fingerprints)
#   nuclei      each web root, the technology and panel templates (-tags tech,panel)
# Tools are on PATH (control/install-stack.sh). Each has a time cap; a tool
# that fails leaves its file empty and the rest goes on. Writes OUT/stack-rows.jsonl.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: stack.sh OUT EXPORT DNS}
export_=${2:?usage: stack.sh OUT EXPORT DNS}
dns=${3:?usage: stack.sh OUT EXPORT DNS}
mkdir -p "$out"
python3 -I "$here/stack_rows.py" targets "$export_" "$out"
printf '%s\n' "$dns" > "$out/resolvers.txt"
start=$(date +%s)

while read -r ip ports; do
  [ -n "$ip" ] && [ -n "$ports" ] || continue
  timeout 600 nmap -sV -Pn -n -p "$ports" -oX "$out/nmap-$ip.xml" "$ip" > /dev/null 2>> "$out/nmap.err"
done < "$out/ports.txt"
nmap_s=$(($(date +%s) - start))

if [ -s "$out/urls.txt" ]; then
  timeout 300 nuclei -ut -silent > /dev/null 2> "$out/nuclei-templates.err" # as a first run fetches them
  timeout 900 httpx -l "$out/urls.txt" -r "$out/resolvers.txt" -td -title -server -ip -json -silent -o "$out/httpx.jsonl" \
    > /dev/null 2> "$out/httpx.err"
  timeout 900 nuclei -l "$out/urls.txt" -r "$out/resolvers.txt" -tags tech,panel -jsonl -silent -duc -o "$out/nuclei.jsonl" \
    > /dev/null 2> "$out/nuclei.err"
fi
python3 -I "$here/stack_rows.py" rows "$out" > "$out/stack-rows.jsonl"
printf '{"nmap_seconds":%d,"seconds":%d}\n' "$nmap_s" $(($(date +%s) - start)) > "$out/stack.json"
