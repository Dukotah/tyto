# Installing tyto

tyto is a local-first AI pentest platform. It runs offline: the planner uses a
local Ollama model, vulnerability data is served from on-disk feeds, and any
external scanners are optional tools you provide. This guide covers building it,
setting up the offline data, and a quickstart.

## Requirements

- Go 1.25+ (only needed to build from source)
- Git
- [Ollama](https://ollama.com) for the local LLM planner
- (Optional) external tools tyto can orchestrate: nuclei, searchsploit /
  Exploit-DB, NetExec. These are invoked as separate processes and are never
  bundled into the binary — install only what you need.

## 1. Build

From the repo root:

```sh
make build
```

This produces `./bin/tyto`. The build stamps the version from `git describe`
into `github.com/dukotah/tyto/pkg/version.Version`.

Install onto your `PATH` (into `GOBIN`):

```sh
make install
```

Verify:

```sh
tyto version
```

To produce release artifacts for all platforms, see the GoReleaser targets:

```sh
make snapshot   # build local archives without publishing
make release    # tag-driven release (CI uses this on v* tags)
```

## 2. Offline data setup

tyto reads its data from `~/.tyto`. Create the layout below.

### nuclei templates

Clone the templates into `~/.tyto/templates` (data only — tyto reads the YAML,
it does not embed it):

```sh
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates \
  ~/.tyto/templates
```

### NVD feeds + CVE index

Download the NVD JSON feeds into `~/.tyto/feeds/nvd`, then build the local CVE
index once. The index makes CVE matching instant and fully offline.

```sh
mkdir -p ~/.tyto/feeds/nvd
# place the NVD JSON feed files in ~/.tyto/feeds/nvd, then:
tyto feeds index
```

This writes `~/.tyto/feeds/cve-index.db`. CVE matching uses it automatically.
You can override the locations:

```sh
tyto feeds index --nvd /path/to/nvd --out /path/to/cve-index.db
```

## 3. Pull an Ollama model

Start Ollama, then pull a `qwen3` model sized to your available RAM:

| RAM        | Suggested model       |
|------------|-----------------------|
| ~8 GB      | `qwen3:4b`            |
| ~16 GB     | `qwen3:8b`            |
| 32 GB+     | `qwen3:14b` / `qwen3:32b` |

```sh
ollama pull qwen3:8b
```

tyto auto-detects a model from available RAM, or you can pin one with
`--model`. The default Ollama endpoint is `http://localhost:11434`.

## 4. Quickstart

### Validate an engagement

Engagements are YAML files describing scope, objectives, and rules of
engagement.

```sh
tyto engagement validate ./my-engagement.yaml
```

### Run an engagement

Plan → guard → execute loop. Start with a dry run (plans and guards only, never
executes tools):

```sh
tyto run --engagement ./my-engagement.yaml --dry-run
```

Then run for real, picking a model if you do not want auto-detection:

```sh
tyto run --engagement ./my-engagement.yaml --model qwen3:8b
```

Useful flags: `--cycles N` (max plan/act cycles), `--report-format md|json|sarif|html`,
`--report-out FILE`, `--resume` with `--state FILE` or `--db FILE`.

### Web console

Drive and monitor engagements in a browser:

```sh
tyto serve            # listens on http://127.0.0.1:8088
tyto serve --addr 0.0.0.0:8088
```

## Where things live

| Path                          | Purpose                          |
|-------------------------------|----------------------------------|
| `~/.tyto/templates`           | nuclei templates (data)          |
| `~/.tyto/feeds/nvd`           | NVD JSON feeds                   |
| `~/.tyto/feeds/cve-index.db`  | built CVE index                  |
| `./bin/tyto`                  | built binary (`make build`)      |
