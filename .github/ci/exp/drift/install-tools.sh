#!/bin/bash
# install-tools.sh: the usual stack for arms A2 and A3, in /opt/tools/bin, where
# both the runner and the agent's user can run it: control/install-stack.sh's
# pinned release binaries (checked against their sha256), anew at a released
# tag, and nuclei's templates fetched once so every epoch uses the same set.
# orvel, which install-stack.sh also puts there, is removed: it is another
# experiment's candidate, not a tool of this one.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=/opt/tools/bin
anew_tag=v0.1.1
sudo install -d -o "$(id -un)" -m 755 /opt/tools "$bin"
"$here/../../control/install-stack.sh" "$bin" > /dev/null
rm -f "$bin/orvel" "$bin/orvel-README.md" "$bin/orvel-stack.tsv"
GOBIN="$bin" go install "github.com/tomnomnom/anew@$anew_tag"
chmod -R a+rX "$bin"
"$bin/nuclei" -update-templates -silent > /dev/null 2>&1 || "$bin/nuclei" -ut > /dev/null 2>&1 || true
echo "install-tools: $(ls "$bin" | wc -l) tools, anew $anew_tag, $(find "$HOME/nuclei-templates" -name '*.yaml' 2> /dev/null | wc -l) nuclei templates"
