#!/bin/bash
# Starts the labs the hunters and the trial use, as they run on the author's
# machine: five training apps, the deploy lab on 5040, the services lab and the DNS lab on 5354. VAmPI
# and DVWA need a first-run step (database); it is done and checked here.
# A sixth, small app changes its routes when it is "deployed": 127.0.0.1:5040,
# `$HOME/lab/deploy v2` deploys, `deploy v1` puts the first version back.
# The apps' images are those of bench/images.env (tag and digest), the list the
# bench's compose file uses too, so the labs are the builds the numbers come from.
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a
# shellcheck source=bench/images.env
. bench/images.env
set +a
sudo sysctl -q -w vm.max_map_count=262144 # Elasticsearch in the services lab
# Every image at once: the pulls wait on the network, so together they take
# as long as the slowest. The images are the values of bench/images.env.
pull() { docker pull -q "$1" > /dev/null || { sleep 5; docker pull -q "$1" > /dev/null; }; }
pids=()
while read -r image; do
  pull "$image" &
  pids+=($!)
done < <(sed -n 's/^AZQ_[A-Z]*_IMAGE=//p' bench/images.env)
docker compose -p azhaq-services -f bench/services.yaml pull -q &
pids+=($!)
for pid in "${pids[@]}"; do
  wait "$pid" || { echo "labs.sh: an image did not pull" >&2; exit 1; }
done
docker run -d --name azq-juice -p 127.0.0.1:3001:3000 -e NODE_OPTIONS=--max-old-space-size=4096 "$AZQ_JUICE_IMAGE"
docker run -d --name azq-vampi -p 127.0.0.1:5002:5000 -e vulnerable=1 -e tokentimetolive=3600 "$AZQ_VAMPI_IMAGE"
docker run -d --name azq-dvga -p 127.0.0.1:5013:5013 -e WEB_HOST=0.0.0.0 "$AZQ_DVGA_IMAGE"
docker run -d --name azq-dvna -p 127.0.0.1:5020:9090 "$AZQ_DVNA_IMAGE"
docker run -d --name azq-dvwa -p 127.0.0.1:5030:80 "$AZQ_DVWA_IMAGE"
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
