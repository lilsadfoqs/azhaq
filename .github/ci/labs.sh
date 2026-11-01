#!/bin/bash
# Starts the labs the hunters and the trial use, as they run on the author's
# machine: five training apps, the deploy lab on 5040, the services lab and the DNS lab on 5354. VAmPI
# and DVWA need a first-run step (database); it is done and checked here.
# A sixth, small app changes its routes when it is "deployed": 127.0.0.1:5040,
# `$HOME/lab/deploy v2` deploys, `deploy v1` puts the first version back.
# The apps' images are pinned by tag and digest, as in bench/images.env and
# bench/compose.yaml (a test keeps the three equal), so the labs are the builds
# the numbers come from.
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
docker run -d --name azq-juice -p 127.0.0.1:3001:3000 -e NODE_OPTIONS=--max-old-space-size=4096 bkimminich/juice-shop:v20.3.0@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27
docker run -d --name azq-vampi -p 127.0.0.1:5002:5000 -e vulnerable=1 -e tokentimetolive=3600 erev0s/vampi:latest@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12
docker run -d --name azq-dvga -p 127.0.0.1:5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga:latest@sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957
docker run -d --name azq-dvna -p 127.0.0.1:5020:9090 appsecco/dvna:sqlite@sha256:2657051b73ac8f879d3a3b419b4618d98e4596a0fe27f8e91582c403541ef1b0
docker run -d --name azq-dvwa -p 127.0.0.1:5030:80 vulnerables/web-dvwa:latest@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
docker compose -p azhaq-services -f bench/services.yaml up -d
mkdir -p "$HOME/lab"
go build -o "$HOME/lab/labdns" ./bench/labdns
nohup "$HOME/lab/labdns" -addr 127.0.0.1:5354 > "$HOME/lab/labdns.log" 2>&1 &
# The deploy lab runs from a copy (the source of a trial's runner is removed);
# the answer key (expected.md) stays behind.
mkdir -p "$HOME/lab/deploy-app"
cp -r bench/truth/deploy/app.py bench/truth/deploy/v1 bench/truth/deploy/v2 "$HOME/lab/deploy-app/"
install -m 755 bench/truth/deploy/deploy.sh "$HOME/lab/deploy"
"$HOME/lab/deploy" v1 > /dev/null
nohup python3 -I "$HOME/lab/deploy-app/app.py" 5040 "$HOME/lab/deploy-app/state" > "$HOME/lab/deploy-app.log" 2>&1 &
for port in 3001 5002 5013 5020 5030 5040; do
  for _ in $(seq 1 120); do
    curl -s -o /dev/null -m 3 "http://127.0.0.1:$port/" && break
    sleep 2
  done
  echo "lab 127.0.0.1:$port: $(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$port/")"
done
dig +short @127.0.0.1 -p 5354 www.azqlab.lan
python3 .github/ci/lab_ready.py --vampi http://127.0.0.1:5002 --dvwa http://127.0.0.1:5030 --deploy http://127.0.0.1:5040
