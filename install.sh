#!/usr/bin/env bash
# Installs OwlAuth Twin on this Mac, or updates it. Safe to run again.
#
#   1. clones the repo to $OWLTWIN_HOME (default ~/owlauthtwin), or pulls it if it is there
#      (when you run this file from a checkout, that checkout is used as it is);
#   2. installs uv with Homebrew if it is missing;
#   3. links `owltwin` into ~/.local/bin and adds that folder to PATH in ~/.zshrc and
#      ~/.bash_profile (one marked block, written once);
#   4. downloads the app's Python packages, so the first `owltwin` starts at once.
#
# Needs git (Xcode Command Line Tools) and a GitHub SSH key with access to the repo; no gh.
# Changes nothing else on the Mac: no certificates, no proxy, no /etc/hosts.
set -euo pipefail

# The GitHub repo does not exist yet: set its SSH URL here once it does.
REPO="${OWLTWIN_REPO:-git@github.com:samsara-dev/owlauthtwin.git}"
DEST="${OWLTWIN_HOME:-$HOME/owlauthtwin}"
BIN="$HOME/.local/bin"
MARK="# owlauthtwin: owltwin on PATH"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'owltwin install: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == Darwin ]] || die "this installs on a Mac; the devbox side is set up by the app"
command -v git >/dev/null || die "git is missing: run xcode-select --install, then this again"

# 1. The repo. Run from a checkout (./install.sh), that checkout is the install.
here=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [[ -n "$here" && -x "$here/owltwin" && -d "$here/app" ]]; then
  DEST="$here"
  say "Using this checkout: $DEST"
elif [[ -d "$DEST/.git" ]]; then
  say "Updating $DEST"
  git -C "$DEST" pull --ff-only --quiet || die "git pull failed in $DEST (local changes?); fix it, then run this again"
elif [[ -e "$DEST" ]]; then
  die "$DEST exists and is not a git checkout; move it away or set OWLTWIN_HOME"
else
  say "Cloning $REPO to $DEST"
  git clone --quiet "$REPO" "$DEST" \
    || die "git clone failed. Check that your GitHub SSH key works: ssh -T git@github.com"
fi

# 2. uv runs the app (Python and its packages, no system Python needed).
if ! command -v uv >/dev/null; then
  command -v brew >/dev/null || die "uv is missing and so is Homebrew; install uv (https://docs.astral.sh/uv/), then run this again"
  say "Installing uv with Homebrew"
  brew install --quiet uv
fi

# 3. `owltwin` on PATH.
mkdir -p "$BIN"
ln -sfn "$DEST/owltwin" "$BIN/owltwin"
say "Linked $BIN/owltwin → $DEST/owltwin"
for rc in "$HOME/.zshrc" "$HOME/.bash_profile"; do
  if ! grep -qF "$MARK" "$rc" 2>/dev/null; then
    # shellcheck disable=SC2016  # written literally, expanded by the shell rc
    printf '\n%s\nexport PATH="$HOME/.local/bin:$PATH"\n' "$MARK" >> "$rc"
    say "Added ~/.local/bin to PATH in ${rc/#"$HOME"/\~}"
  fi
done

# 4. The app's packages, ahead of the first start.
say "Downloading the app's Python packages"
(cd "$DEST/app" && uv sync --quiet --frozen --no-dev)

command -v devbox >/dev/null || say "Note: the devbox CLI is not on PATH; the app needs it to list and connect devboxes"

cat <<EOF

OwlAuth Twin is installed. Open a new terminal (or run: export PATH="\$HOME/.local/bin:\$PATH"), then:

  owltwin           start the app and open the panel
  owltwin update    get the latest version
EOF
