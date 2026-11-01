#!/bin/bash
# Starts the labs the hunters and the trial use, as they run on the author's
# machine: five training apps, the services lab and the DNS lab on 5354.
set -euo pipefail
cd "$(dirname "$0")/../.."
sudo sysctl -q -w vm.max_map_count=262144 # Elasticsearch in the services lab
# Every image at once: the pulls wait on the network, so together they take
# as long as the slowest. The images are the last word of each `docker run`
# below, so the list cannot drift from the containers.
pull() { docker pull -q "$1" > /dev/null || { sleep 5; docker pull -q "$1" > /dev/null; }; }
pids=()
while read -r image; do
  pull "$image" &
  pids+=($!)
done < <(grep '^docker run' "${BASH_SOURCE[0]}" | awk '{print $NF}')
docker compose -p azhaq-services -f bench/services.yaml pull -q &
pids+=($!)
for pid in "${pids[@]}"; do
  wait "$pid" || { echo "labs.sh: an image did not pull" >&2; exit 1; }
done
docker run -d --name azq-juice -p 127.0.0.1:3001:3000 -e NODE_OPTIONS=--max-old-space-size=4096 bkimminich/juice-shop
docker run -d --name azq-vampi -p 127.0.0.1:5002:5000 -e vulnerable=1 -e tokentimetolive=3600 erev0s/vampi
docker run -d --name azq-dvga -p 127.0.0.1:5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga:latest
docker run -d --name azq-dvna -p 127.0.0.1:5020:9090 appsecco/dvna:sqlite
docker run -d --name azq-dvwa -p 127.0.0.1:5030:80 vulnerables/web-dvwa
docker compose -p azhaq-services -f bench/services.yaml up -d
mkdir -p "$HOME/lab"
go build -o "$HOME/lab/labdns" ./bench/labdns
nohup "$HOME/lab/labdns" -addr 127.0.0.1:5354 > "$HOME/lab/labdns.log" 2>&1 &
for port in 3001 5002 5013 5020 5030; do
  for _ in $(seq 1 120); do
    curl -s -o /dev/null -m 3 "http://127.0.0.1:$port/" && break
    sleep 2
  done
  echo "lab 127.0.0.1:$port: $(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$port/")"
done
dig +short @127.0.0.1 -p 5354 www.azqlab.lan
