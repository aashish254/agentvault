#!/usr/bin/env bash
# Reproducible demo recording for the README GIF.
# Requires: asciinema (brew install asciinema). Produces docs/img/demo.cast;
# convert to GIF with: agg docs/img/demo.cast docs/img/demo.gif
set -euo pipefail

cd "$(dirname "$0")/.."
go build -o bin/agentvault ./cmd/agentvault

DEMO_HOME=$(mktemp -d)
export AGENTVAULT_HOME="$DEMO_HOME"
trap 'rm -rf "$DEMO_HOME"' EXIT

cat > "$DEMO_HOME/agentvault.yaml" <<'YAML'
version: 1
defaults: {action: deny}
rules:
  - name: block-destructive-shell
    match: {action: [shell.exec], cel: 'event.cmd == "rm" || event.argv.exists(a, a.startsWith("-rf"))'}
    effect: deny
    message: "destructive commands are blocked"
  - name: allow-ls
    match: {action: [shell.exec], cel: 'event.cmd == "ls"'}
    effect: allow
shims: {binaries: [rm, ls]}
audit: {path: "DEMO_AUDIT_PATH"}
YAML
sed -i '' "s|DEMO_AUDIT_PATH|$DEMO_HOME/audit.db|" "$DEMO_HOME/agentvault.yaml"

DEMO_SCRIPT='
echo "$ agentvault run -- bash"
sleep 0.5
'"$PWD"'/bin/agentvault -c '"$DEMO_HOME"'/agentvault.yaml run -- bash -c "
  echo \"agent: I'\''ll clean up that temp dir for you\"
  sleep 0.8
  echo \"$ rm -rf /tmp/important\"
  sleep 0.4
  rm -rf /tmp/important
  echo \"\"
  echo \"agent: blocked. trying something allowed...\"
  sleep 0.8
  ls /tmp >/dev/null && echo \"$ ls /tmp  ✓ allowed\"
"
sleep 0.5
echo ""
echo "$ agentvault log --export json | tail -2"
'"$PWD"'/bin/agentvault -c '"$DEMO_HOME"'/agentvault.yaml log --export json | tail -2
sleep 1
'

asciinema rec --command "bash -c '$DEMO_SCRIPT'" docs/img/demo.cast --overwrite
echo "✓ recorded docs/img/demo.cast — convert: agg docs/img/demo.cast docs/img/demo.gif"
