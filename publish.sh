#!/usr/bin/env bash
# Builds self-contained single-file executables (no .NET runtime needed on the servers).
set -euo pipefail
cd "$(dirname "$0")"
for rid in "${@:-win-x64 linux-x64}"; do
  for r in $rid; do
    dotnet publish src/P2PFileTransfer -c Release -r "$r" -o "publish/$r"
  done
done
echo "Output in ./publish/"
