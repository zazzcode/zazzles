# Getting started

[Documentation index](README.md) · Next: [Run a scan](running-scans.md)

Run the following commands from the scanner checkout root, alongside `go.mod`.

## Setup

1. Install Go 1.27.2 or newer. Check with `go version`.
2. Install a C compiler and keep it on `PATH`. The Tree-sitter bindings use cgo. On macOS
   that is the Xcode command line tools (`xcode-select --install`).
3. Clone this repository and enter its root, the directory that contains `go.mod`. Contributors
   use the feature-worktree setup described under [contributor guide](contributing.md).
4. The first `go run` or `go test` downloads the modules in `go.mod`. No separate install step.

The program scans a directory you already have on disk. It does not clone, install, or start
the target application.

### Compile

Build a local executable from the directory containing `go.mod`:

```bash
go build -o bin/scan ./cmd/scan
./bin/scan --list /path/to/app
```

### Local environment file

The tracked [.env.sample](../.env.sample) lists supported local environment settings with empty key
fields. For a new setup, copy it to `.env`. If `.env` already exists, merge only the needed settings;
do not replace your existing keys. `.env` stays Git-ignored.

```bash
cp .env.sample .env  # New setups only; do not overwrite an existing .env.
```

Set the output root in `.env`, adjusting the path for your checkout layout:

```bash
SCAN_FINDINGS_DIR="$HOME/zazzles-findings"
```

Load your own trusted `.env` in bash or zsh before running scan:

```bash
set -a
. ./.env
set +a
```

The scanner reads environment variables and does not auto-load `.env`. This sample is for local
shell use; CI should set environment variables and secrets through its workflow configuration.

To load `.env` automatically on `cd` into the checkout, use [direnv](https://direnv.net) with the
tracked `.envrc` (it only says `dotenv` and reads the Git-ignored `.env`):

```bash
brew install direnv            # macOS; see direnv docs for other shells/OSes
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc   # once per machine; reload your shell
direnv allow                    # once per checkout, after reviewing .envrc
```

Every worktree of this repository has its own `.env` and needs its own `direnv allow`.


Build and run an offline scan to inspect source evidence. Enable `--judge` after configuring a
provider if you want model assessment. [Running scans](running-scans.md#run) ·
[Decision-model setup](decision-models.md#credentials-and-local-environment)
