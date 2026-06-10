#!/usr/bin/env bash
# tyto — one-shot Kali (WSL2) setup. Run AFTER `wsl --install -d kali-linux`.
# Installs the tools tyto's adapters drive, links your existing offline data, and
# stages the linux binary. Idempotent: safe to re-run.
set -uo pipefail

WINUSER="${WINUSER:-dukot}"
TYTO_DATA="/mnt/c/Users/${WINUSER}/.tyto"
TYTO_BIN="/mnt/c/Users/${WINUSER}/tyto/bin/tyto-linux-amd64"

echo "==> Installing pentest tools (this pulls several GB incl. metasploit)…"
sudo apt-get update -y
# Core arsenal the adapters drive. Names per Kali apt.
sudo apt-get install -y \
  nmap nuclei sqlmap ffuf gobuster nikto whatweb wpscan hydra \
  dnsutils dirb metasploit-framework netexec exploitdb || true
# These vary by repo/version — best-effort, report if missing.
sudo apt-get install -y subfinder  2>/dev/null || echo "  [!] subfinder: install manually (apt or 'go install ...subfinder') if needed"
sudo apt-get install -y testssl.sh 2>/dev/null || echo "  [!] testssl.sh: install manually if needed"

echo "==> Linking your existing tyto data (${TYTO_DATA})…"
if [ -e "${TYTO_DATA}" ]; then ln -sfn "${TYTO_DATA}" "${HOME}/.tyto"; else echo "  [!] ${TYTO_DATA} not found — adjust WINUSER"; fi

echo "==> Staging the tyto binary…"
cp "${TYTO_BIN}" "${HOME}/tyto" && chmod +x "${HOME}/tyto"

echo "==> Verifying which adapters are now live (detected on PATH):"
for t in nmap nuclei sqlmap ffuf gobuster nikto whatweb wpscan hydra subfinder testssl.sh msfconsole netexec searchsploit; do
  if command -v "$t" >/dev/null 2>&1; then echo "  [+] $t"; else echo "  [-] $t (adapter will degrade gracefully)"; fi
done

echo "==> tyto:"; "${HOME}/tyto" version; echo "tools: $("${HOME}/tyto" tools | grep -c category)"
HOSTIP="$(grep -m1 nameserver /etc/resolv.conf | awk '{print $2}')"
echo
echo "Done. Start the console (open http://localhost:8088 in your Windows browser):"
echo "  ~/tyto serve --addr 0.0.0.0:8088 --ollama-url http://${HOSTIP}:11434"
