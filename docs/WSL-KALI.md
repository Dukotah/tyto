# Running tyto on Kali (WSL2)

This machine already has Hyper-V active, so **WSL2 + Kali** is the right runtime
(VirtualBox would conflict with Hyper-V). WSL2-Kali is lighter, sees your Windows
files directly, and exposes tyto's console to your Windows browser at
`localhost:8088`.

## 1. Install Kali (Administrator PowerShell, one time)
```powershell
wsl --install -d kali-linux
```
Reboot if prompted; on first launch create a username + password. Then open the
**Kali** terminal for the rest.

## 2. Get the tools tyto's adapters drive (in Kali)
Kali-WSL ships minimal. Install the heavy hitters:
```bash
sudo apt update
sudo apt -y install nmap nuclei sqlmap ffuf netexec exploitdb hydra
```
(You can also `sudo apt -y install kali-linux-default` for the full toolset — larger.)

## 3. Point tyto at your existing data + binary (no copy needed)
Your Windows files are visible from Kali under `/mnt/c`. Symlink the data tyto
already built on Windows, and grab the prebuilt Linux binary:
```bash
# the offline data (templates + 250k-CVE index) you already downloaded on Windows
ln -s /mnt/c/Users/dukot/.tyto ~/.tyto

# the statically-linked linux binary
cp /mnt/c/Users/dukot/tyto/bin/tyto-linux-amd64 ~/tyto
chmod +x ~/tyto
~/tyto version && ~/tyto tools | wc -l   # sanity check
```

## 4. Wire the AI model (host Ollama)
Ollama is already running on Windows. Pick the model you have:
```bash
export TYTO_MODEL=qwen3:14b
# Find the Windows host IP as seen from WSL2 (used as --ollama-url below):
HOSTIP=$(grep nameserver /etc/resolv.conf | awk '{print $2}'); echo "host = $HOSTIP"
```
(Or skip the model entirely and use `--planner scripted` for a deterministic run.)

## 5. Run it
```bash
# operational console — open http://localhost:8088 in your WINDOWS browser.
# Point --ollama-url at the host (try localhost first; fall back to $HOSTIP):
~/tyto serve --addr 0.0.0.0:8088 --ollama-url http://$HOSTIP:11434
```
Or a headless CLI run against an **authorized** engagement:
```bash
~/tyto run --engagement my-engagement.yaml --planner ollama \
  --model qwen3:14b --ollama-url http://$HOSTIP:11434 --cycles 3
```

## Authorization — non-negotiable
tyto only tests what an engagement's scope + authorization permit. Only ever
point it at: your own assets, a signed engagement, or an in-scope bug-bounty
program you're enrolled in. The scope guard refuses everything else; you supply
the permission.

## Two starter engagements
- **Authorized lab (full exploit):** `allowed_categories: [recon, scan, exploit]`,
  `max_risk: high`, with an Ed25519 grant (`tyto authorize keygen|sign`).
- **Bug-bounty / external (scan-only):** `allowed_categories: [recon, scan]` — no
  exploitation; recon + PoC discovery that respects program rules.
