#!/usr/bin/env bash
# Installs Ubuntu packages on a GitHub-hosted runner. Without packages it only reorders the
# mirrors, for a tool that installs packages itself, such as Playwright. The runner's mirror list
# starts with a cloud mirror that sometimes serves packages at about 100 kB/s
# (actions/runner-images#14823), and apt moves to the next mirror only when one fails, so apt
# tries Ubuntu's own archive first and that mirror last.
set -euo pipefail
sudo sed -i 's/\tpriority:1$/\tpriority:4/' /etc/apt/apt-mirrors.txt
if [ "$#" -gt 0 ]; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends "$@"
fi
