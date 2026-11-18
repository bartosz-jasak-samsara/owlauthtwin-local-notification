"""Server-side route from the devbox backend to the Twin on the Mac.

  backend on devbox ──► us.agent.workday.com (/etc/hosts → 127.0.0.1)
                   ──► 127.0.0.1:443   socat (root, loopback only)
                   ──► 127.0.0.1:18443 ssh -R from the Mac
                   ──► Twin server listener on the Mac

Changes on the devbox: /etc/hosts lines ending in "# OWLTWIN" and a tmux
session "owltwin-fwd" running socat (both removed by `down`), plus
~/.owltwin/ (CA bundle for SSL_CERT_FILE), which stays so a running backend
keeps working.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field

MARKER = "OWLTWIN"
REMOTE_PORT = 18443
LOCAL_YAML = "~/co/aiml-agents/agent-platform/agents/ml/claude_core/config/local.yaml"
RUN_SESSION = "owltwin-run"   # tmux session on the devbox where OwlAuth Twin starts the projects
SHELLS = {"bash", "zsh", "sh", "fish", ""}
ERROR_PATTERN = (
    "command not found|is blocked|error|fatal|panic|no such file|failed|exited with|traceback"
)
SSO_PATTERN = (
    "caller identity|sso session|token has expired|aws sso login|SSOTokenLoadError"
    "|InvalidGrantException|refresh failed"
)

# Plain string (not an f-string): tmux formats use braces.
BYPANE = r"""
# Processes started in pane $1 of this tmux server, also those re-parented to init (uv run is).
# git's fsmonitor daemon is git's own and is left alone.
bypane() {
  sock=$(tmux display -p '#{socket_path}' 2>/dev/null)
  for p in $(pgrep -u "$(id -u)"); do
    env=$( { tr '\0' '\n' < /proc/$p/environ; } 2>/dev/null) || continue
    printf '%s\n' "$env" | grep -qx "TMUX_PANE=$1" || continue
    printf '%s\n' "$env" | grep -q "^TMUX=$sock," || continue
    grep -q fsmonitor /proc/$p/cmdline 2>/dev/null && continue
    echo "$p"
  done
}
"""


AGENTS_ENVRC = "$HOME/co/aiml-agents/.envrc.local"

# AWS SSO sign-in without copying anything: the device flow runs on the devbox and OwlAuth Twin
# opens its page, code already filled in, in your browser on this Mac. The devbox profiles share
# one sso-session, so one sign-in renews them all: that of OWLTWIN_AWS_PROFILE (or of its
# sso-<profile> entry) when it is set, else the one most profiles in the devbox's ~/.aws/config
# use, else its first.
SSO_LOGIN = r"""
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE
s=""
if [ -n "$P" ]; then
  s=$(aws configure get sso_session --profile "$P" 2>/dev/null ||
      aws configure get sso_session --profile "sso-$P" 2>/dev/null)
fi
# The sso-session most profiles use: a config can keep an old one (samsara-legacy, say) first.
[ -n "$s" ] || s=$(awk '$1 == "sso_session" {print $3}' ~/.aws/config 2>/dev/null |
  sort | uniq -c | sort -rn | awk 'NR == 1 {print $2}')
[ -n "$s" ] || s=$(sed -n 's/^\[sso-session \(.*\)\]$/\1/p' ~/.aws/config 2>/dev/null | head -n 1)
[ -n "$s" ] || { echo "no sso-session in the devbox's ~/.aws/config"; exit 1; }
exec timeout 600 aws sso login --sso-session "$s" --use-device-code --no-browser
"""


def sso_login(alias: str, on_url) -> str:
    """Runs the device sign-in and calls on_url(url) once the page with the code is known.
    Blocks until you finish in the browser (or 10 minutes). Returns an error, or ""."""
    p = subprocess.Popen(
        [*SSH, alias, "bash -s"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    assert p.stdin and p.stdout
    profile = os.environ.get("OWLTWIN_AWS_PROFILE", "").strip()
    p.stdin.write(f"P={shlex.quote(profile)}\n" + SSO_LOGIN)
    p.stdin.close()
    last = ""
    for line in p.stdout:
        line = line.strip()
        if line.startswith("https://") and "user_code=" in line:
            on_url(line)
        elif line and not line.startswith("https://"):
            last = line
    rc = p.wait()
    if rc == 124:
        return "not confirmed in the browser within 10 minutes"
    return "" if rc == 0 else (last or "aws sso login failed")[:200]


# Agent Studio access for the org you log in with. The local backend evaluates these flags against
# production LaunchDarkly, where the org is not targeted; a local override in dynamodb-local (table
# feature-flag-overrides, the one /internal/release_management/feature_flag_overrides edits) puts
# them in the org's enabled flags.
DEFAULT_ORG = int(os.environ.get("OWLTWIN_ORG", "205"))
DEFAULT_FLAGS = ("agent-studio-enabled", "credits-experience-enabled")
DDB = (
    "unset AWS_PROFILE AWS_DEFAULT_PROFILE; "
    "export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_DEFAULT_REGION=us-west-2; "
    'ddb() { timeout 20 aws --endpoint-url http://127.0.0.1:8768 dynamodb "$@"; }'
)


def override_status(org: int) -> str:
    """Prints "ddb" when dynamodb-local answers, then "ovr <flag>" per direct override."""
    return DDB + f"""
if out=$(ddb query --table-name feature-flag-overrides --key-condition-expression "PK = :p" \\
     --expression-attribute-values '{{":p":{{"S":"ORGFLAGS#{int(org)}"}}}}' --output json 2>/dev/null); then
  echo ddb
  printf '%s' "$out" | python3 -c '
import json, sys
for i in json.load(sys.stdin).get("Items", []):
    if "direct" in i.get("Sources", {{}}).get("SS", []):
        print("ovr " + i["SK"]["S"].removeprefix("FLAG#"))'
fi
"""  # noqa: E501


def _S(v: str) -> dict[str, str]:  # a DynamoDB string attribute
    return {"S": v}


def _q(d: dict) -> str:  # d as JSON for the j() helper, quoted for the shell
    return '"$(j ' + shlex.quote(json.dumps(d)) + ')"'


def _run_ddb(alias: str, lines: list[str]) -> str:
    head = [
        DDB, "set -e", "now=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)", "T=feature-flag-overrides",
        "j() { printf '%s' \"$1\" | sed \"s/@NOW@/$now/g\"; }",
    ]
    try:
        r = rsh(alias, "\n".join(head + lines) + "\n", timeout=120)
    except subprocess.TimeoutExpired:
        return "dynamodb-local did not answer"
    if r.returncode == 0:
        return ""
    err_lines = (r.stderr or r.stdout or "failed").strip().splitlines() or ["failed"]
    return err_lines[-1][:200]


def ensure_overrides(alias: str, org: int, flags: list[str]) -> str:
    """Adds the org to each flag's overrides as the panel does: the flag, its direct org, the
    materialized row. Existing rows are kept (conditional puts; the source set only gains
    "direct"). Returns an error, or ""."""
    o = {"N": str(int(org))}
    lines: list[str] = []
    for f in flags:
        meta = {
            "PK": _S(f"FLAG#{f}"),
            "SK": _S("#META"),
            "FlagKey": _S(f),
            "SearchName": _S(f),
            "Description": _S("Local dev only: OwlAuth Twin"),
            "GSI1PK": _S("ALL_FLAGS"),
            "GSI1SK": _S(f"FLAG#{f}"),
            "GSI2PK": _S("FLAGS"),
            "GSI2SK": _S(f"@NOW@#{f}"),
            "CreatedAt": _S("@NOW@"),
            "UpdatedAt": _S("@NOW@"),
        }
        direct = {
            "PK": _S(f"FLAG#{f}"),
            "SK": _S(f"DIRECT_ORG#{org}"),
            "FlagKey": _S(f),
            "OrgId": o,
            "AddedAt": _S("@NOW@"),
        }
        key = {"PK": _S(f"ORGFLAGS#{org}"), "SK": _S(f"FLAG#{f}")}
        vals = {
            ":d": {"SS": ["direct"]},
            ":f": _S(f),
            ":o": o,
            ":g": _S("MATERIALIZED_FLAGS"),
            ":k": _S(f"ORGFLAGS#{org}#FLAG#{f}"),
            ":t": _S("@NOW@"),
        }
        lines += [
            f"ddb put-item --table-name $T --item {_q(meta)}"
            " --condition-expression 'attribute_not_exists(PK)' >/dev/null 2>&1 || true",
            f"ddb put-item --table-name $T --item {_q(direct)}"
            " --condition-expression 'attribute_not_exists(PK)' >/dev/null 2>&1 || true",
            f"ddb update-item --table-name $T --key {_q(key)} --update-expression "
            "'ADD Sources :d SET FlagKey = :f, OrgId = :o, GSI3PK = :g, GSI3SK = :k, "
            "UpdatedAt = :t' "
            f"--expression-attribute-values {_q(vals)} >/dev/null",
        ]
    return _run_ddb(alias, lines)


def remove_overrides(alias: str, org: int, flags: list[str]) -> str:
    """Takes the org's direct override off each flag: the direct-org row goes, the materialized
    row loses "direct" and goes when no other source is left. Flag rows stay (other orgs may use
    them). Returns an error, or ""."""
    lines: list[str] = []
    for f in flags:
        direct = {"PK": _S(f"FLAG#{f}"), "SK": _S(f"DIRECT_ORG#{org}")}
        key = {"PK": _S(f"ORGFLAGS#{org}"), "SK": _S(f"FLAG#{f}")}
        lines += [
            f"ddb delete-item --table-name $T --key {_q(direct)} >/dev/null",
            f"ddb update-item --table-name $T --key {_q(key)} --update-expression "
            "'DELETE Sources :d' --condition-expression 'attribute_exists(PK)' "
            f"--expression-attribute-values {_q({':d': {'SS': ['direct']}})} "
            ">/dev/null 2>&1 || true",
            f"ddb delete-item --table-name $T --key {_q(key)} "
            "--condition-expression 'attribute_not_exists(Sources)' >/dev/null 2>&1 || true",
        ]
    return _run_ddb(alias, lines)


# Both repos want Redis on 127.0.0.1:6380. aiml-agents' `make server` reuses whatever answers
# there and only starts its own (redis7) when nothing does; the backend's compose service cannot
# share the port.
REDIS_BACKEND = "backend-redis-1"
REDIS_AGENTS = "redis7"
FREE_REDIS_CMD = (
    f"docker stop {REDIS_AGENTS} && (docker start {REDIS_BACKEND} 2>/dev/null "
    "|| (cd ~/co/backend && docker compose up -d redis))"
)


def free_redis(alias: str) -> str:
    """Hands :6380 from aiml-agents' redis7 to the backend's Redis. Returns an error, or ""."""
    r = rsh(alias, FREE_REDIS_CMD + " >/dev/null", timeout=90)
    if r.returncode != 0:
        return ((r.stderr or r.stdout or "failed").strip().splitlines() or ["failed"])[-1][:200]
    return ""


RUN_STATUS = r"""
PANES=" $(tmux list-panes -s -t '=owltwin-run' -F '#{pane_pid}' 2>/dev/null | tr '\n' ' ') "
ours() {
  p=$1
  while [ -n "$p" ] && [ "$p" -gt 1 ] 2>/dev/null; do
    case "$PANES" in *" $p "*) return 0;; esac
    p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
  done
  return 1
}
apid=$(ss -ltnpH 'sport = :8000' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
[ -n "$apid" ] && ours "$apid" && echo agents_ours
bpid=$(pgrep -x agentconnectors | head -1)
[ -n "$bpid" ] && ours "$bpid" && echo backend_ours
# One line per project pane, found by its @owltwin mark (or, from before the mark, a window's first pane).
for row in $(tmux list-panes -s -t '=owltwin-run' -F '#{pane_id}|#{@owltwin}|#{window_name}|#{pane_index}|#{pane-base-index}' 2>/dev/null); do
  IFS='|' read -r T w wn pi base <<<"$row"
  [ -z "$w" ] && [ "$pi" = "${base:-0}" ] && w=$wn
  [ -z "$w" ] && continue
  # The terminal's foreground process group tells a running job from an idle shell. tmux's
  # pane_current_command says "bash" for a bash script such as taskrunner-localdev.
  pp=$(tmux display -p -t "$T" '#{pane_pid}' 2>/dev/null)
  fg=$(ps -o tpgid= -p "$pp" 2>/dev/null | tr -d ' ')
  if [ -n "$fg" ] && [ "$fg" != "$pp" ] && [ "$fg" -gt 0 ] 2>/dev/null; then
    echo "win $w run:$(ps -o comm= -p "$fg" 2>/dev/null)"
  else
    echo "win $w $(tmux display -p -t "$T" '#{pane_current_command}' 2>/dev/null)"
  fi
  out=$(tmux capture-pane -p -t "$T" -S -80 2>/dev/null)
  echo "tail $w $(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -1 | cut -c1-220)"
  printf '%s\n' "$out" | grep -qiE 'SSO_PATTERN' && echo "sso $w"
  e=$(printf '%s\n' "$out" | grep -iE 'ERROR_PATTERN' | tail -1 | cut -c1-220)
  [ -n "$e" ] && echo "err $w $e"
done
# taskrunner tasks whose last status in this run is Failed: a side task can fail while the services run.
trp=$(pgrep -f 'bin/taskrunner-localdev' | head -1)
if [ -n "$trp" ]; then
  since=$(( $(date +%s) - $(ps -o etimes= -p "$trp" | tr -d ' ') ))
  for f in $(find /tmp/taskrunner-realtime-logs -maxdepth 1 -name '*.log' -newermt "@$since" 2>/dev/null); do
    case "$(grep -oE 'm(Started|Completed|Failed)\\u001b\[0m' "$f" | tail -1)" in
      mFailed*) echo "tfail backend $(grep -oE '"task":"[^"]+"' "$f" | tail -1 | cut -d'"' -f4)";;
    esac
  done
fi
true
""".replace("SSO_PATTERN", SSO_PATTERN).replace("ERROR_PATTERN", ERROR_PATTERN)  # noqa: E501


_TMUX_LOCKS: dict[str, threading.Lock] = {}
_TMUX_LOCKS_GUARD = threading.Lock()


def _tmux_lock(alias: str) -> threading.Lock:
    with _TMUX_LOCKS_GUARD:
        return _TMUX_LOCKS.setdefault(alias, threading.Lock())


def run_in_window(alias: str, window: str, cwd: str, cmd: str) -> str:
    """Runs cmd in the owltwin-run:<window> tmux pane on the devbox, stopping what ran there before.

    Only touches OwlAuth Twin's own tmux session; the shell stays open so the log stays readable
    (tmux attach -t owltwin-run). Returns '' or an error."""
    typed = shlex.quote(f"clear; {AGENT_EXPORT} cd {cwd} && {cmd}")
    template = r"""
set -u
S=owltwin-run
W=WINDOW
# Each project's pane carries @owltwin=<name>, so it is found however you rearrange the windows
# (join-pane, splits, renames). Panes from before the mark: the first pane of the window of that name.
T=""
if tmux has-session -t "=$S" 2>/dev/null; then
  T=$(tmux list-panes -s -t "=$S" -F '#{pane_id} #{@owltwin}' | awk -v w="$W" '$2 == w {print $1; exit}')
  if [ -z "$T" ] && tmux list-windows -t "=$S" -F '#{window_name}' | grep -qx "$W"; then
    T=$(tmux list-panes -t "=$S:$W" -F '#{pane_id} #{@owltwin}' | awk 'NF == 1 {print $1; exit}')
  fi
  [ -z "$T" ] && T=$(tmux new-window -d -P -F '#{pane_id}' -t "=$S" -n "$W" -c CWD)
else
  T=$(tmux new-session -d -P -F '#{pane_id}' -s "$S" -n "$W" -c CWD) || T=""
  tmux set-option -t "=$S" remain-on-exit on >/dev/null
fi
if [ -z "$T" ]; then echo "no tmux pane for $W in $S" >&2; exit 1; fi
tmux set-option -p -t "$T" @owltwin "$W"
busy() { p=$(tmux display -p -t "$T" '#{pane_pid}'); g=$(ps -o tpgid= -p "$p" | tr -d ' '); [ -n "$g" ] && [ "$g" != "$p" ] && [ "$g" -gt 0 ]; }
desc() { for c in $(pgrep -P "$1"); do echo "$c"; desc "$c"; done; }
BYPANE
ours() { P=$(tmux display -p -t "$T" '#{pane_pid}'); { desc "$P"; bypane "$(tmux display -p -t "$T" '#{pane_id}')"; } | grep -vx "$P" | sort -u; }
gone() { ! busy && [ -z "$(ours)" ]; }
if busy; then
  tmux send-keys -t "$T" C-c
  for i in $(seq 1 10); do busy || break; sleep 1; done
fi
if ! gone; then
  kids=$(ours)
  [ -n "$kids" ] && kill -TERM $kids 2>/dev/null
  for i in $(seq 1 10); do gone && break; sleep 1; done
  kids=$(ours)
  [ -n "$kids" ] && kill -KILL $kids 2>/dev/null
  sleep 1
fi
tmux clear-history -t "$T"
tmux send-keys -t "$T" -l TYPED
tmux send-keys -t "$T" Enter
"""  # noqa: E501
    script = (
        template.replace("BYPANE", BYPANE)
        .replace("WINDOW", shlex.quote(window))
        .replace("CWD", cwd)
        .replace("TYPED", typed)
    )
    try:
        with _tmux_lock(alias):  # two projects starting at once would both create owltwin-run
            r = rsh(alias, script, timeout=90)
    except subprocess.TimeoutExpired:
        return f"tmux on the devbox did not answer while starting {window}"
    if r.returncode == 0:
        return ""
    return (r.stderr or r.stdout or f"could not start {window}").strip()[-300:]


ENVRC_DIRS = ("~/co/backend", "~/co/aiml-agents/agent-platform", "~/co/aiml-agents")


def direnv_allow(alias: str) -> str:
    """Approves the repos' .envrc files, as their own guides ask; a fresh clone has them blocked."""
    script = "set -u\nbad=0\n" + "".join(
        f'if [ -f {d}/.envrc ]; then (cd {d} && direnv allow . >/dev/null 2>&1); '
        f'(cd {d} && direnv exec . true >/dev/null 2>&1) || {{ echo "blocked {d}"; bad=1; }}; fi\n'
        for d in ENVRC_DIRS
    ) + "exit $bad\n"
    try:
        r = rsh(alias, script, timeout=120)
    except subprocess.TimeoutExpired:
        return "direnv allow timed out on the devbox"
    if r.returncode == 0:
        return ""
    blocked = " ".join(
        line.split(" ", 1)[1] for line in r.stdout.splitlines() if line.startswith("blocked ")
    )
    return (
        "direnv could not load .envrc in: " + blocked
        or (r.stderr or "direnv allow failed").strip()[-200:]
    )


MERGE_LOCAL_YAML = r"""
import os, shutil, sys
from ruamel.yaml import YAML
f = os.path.expanduser(sys.argv[1])
y = YAML()
y.preserve_quotes = True
with open(f) as fh:
    d = y.load(fh)
if d is None:
    d = {}
if not isinstance(d, dict) or not isinstance(d.setdefault("agent_config", {}), dict) \
        or not isinstance(d["agent_config"].setdefault("sandbox_client", {}), dict):
    print("local.yaml is not a mapping with agent_config.sandbox_client", file=sys.stderr)
    sys.exit(2)
sc = d["agent_config"]["sandbox_client"]
if sc.get("provider") == "local_docker":
    sys.exit(0)
if not os.path.exists(f + ".owltwin-backup"):
    shutil.copy2(f, f + ".owltwin-backup")
old = sc.get("provider")
sc["provider"] = "local_docker"
with open(f, "w") as fh:
    y.dump(d, fh)
print(f"MERGED {old}")
"""


def write_sandbox_config(alias: str) -> str:
    """Puts agent_config.sandbox_client.provider: local_docker in claude_core's local.yaml.

    A missing file is created; an existing one gets just that key (comments kept, ruamel.yaml from
    aiml-agents' venv) and a one-time copy at local.yaml.owltwin-backup. Returns an error,
    "merged" when it edited your file, or ""."""
    script = f"""
set -eu
f={LOCAL_YAML}
if [ ! -e "$f" ]; then
  mkdir -p "$(dirname "$f")"
  printf 'agent_config:\\n  sandbox_client:\\n    provider: local_docker\\n' > "$f"
  exit 0
fi
py=~/co/aiml-agents/agent-platform/.venv/bin/python
[ -x "$py" ] || {{ echo "aiml-agents has no venv yet (aiml-agents setup makes it)" >&2; exit 4; }}
"$py" - "$f" <<'PY'
{MERGE_LOCAL_YAML}
PY
"""
    r = rsh(alias, script, timeout=60)
    if r.returncode != 0:
        return (r.stderr or "could not write local.yaml").strip()[-300:]
    return "merged" if "MERGED" in r.stdout else ""


# Stops a project you started yourself, after you clicked Take over: the whole process tree from
# the process your shell started (make, taskrunner-localdev) down. Ctrl+C-like TERM first, KILL
# after 15 s.
STOP_OWN = r"""
case WHAT in
  agents) pid=$(ss -ltnpH 'sport = :8000' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2);;
  backend) pid=$(pgrep -x agentconnectors | head -1);;
esac
[ -z "${pid:-}" ] && exit 0
top=$pid
while :; do
  pp=$(ps -o ppid= -p "$top" | tr -d ' ')
  { [ -z "$pp" ] || [ "$pp" -le 1 ]; } && break
  [ "$pp" = "$(ps -o sid= -p "$pp" | tr -d ' ')" ] && break   # the parent is your shell (session leader)
  top=$pp
done
desc() { for c in $(pgrep -P "$1"); do echo "$c"; desc "$c"; done; }
all="$top $(desc "$top")"
alive() { for p in $all; do [ -d /proc/$p ] && echo "$p"; done; }
kill -TERM $all 2>/dev/null
for i in $(seq 1 15); do [ -z "$(alive)" ] && break; sleep 1; done
k=$(alive); [ -n "$k" ] && kill -KILL $k 2>/dev/null
echo "stopped $(ps -o comm= -p "$top" 2>/dev/null || echo "$top")"
true
"""  # noqa: E501


def stop_own(alias: str, what: str) -> str:
    if what not in ("agents", "backend"):
        return f"unknown project {what}"
    try:
        r = rsh(alias, STOP_OWN.replace("WHAT", what), timeout=60)
    except subprocess.TimeoutExpired:
        return "the devbox did not answer"
    return "" if r.returncode == 0 else (r.stderr or "could not stop it").strip()[-200:]


SANDBOX_IMAGES = ("samsara/agentsandbox-code-v1:local", "samsara/agentsandbox-code-v2:local")
# tmux panes keep the SSH_AUTH_SOCK of the short ssh that created them, which is gone a second
# later, so git over ssh (taskrunner's pull/feature-flags) fails with "Permission denied
# (publickey)". The tunnel's ssh stays connected and forwards the agent as your ssh config says
# (ForwardAgent); it keeps a link to its socket, and the commands OwlAuth Twin starts use that
# link. Nothing changes when the agent is not forwarded.
AGENT_LINK = "$HOME/.owltwin/agent.sock"
TUNNEL_CMD = (
    '[ -n "$SSH_AUTH_SOCK" ] && mkdir -p ~/.owltwin'
    ' && ln -sfn "$SSH_AUTH_SOCK" ~/.owltwin/agent.sock; '
    "exec cat >/dev/null"  # ends when the connection does: stdin closes
)
AGENT_EXPORT = f'[ -S "{AGENT_LINK}" ] && export SSH_AUTH_SOCK="{AGENT_LINK}";'

SSH = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "ControlMaster=no",
    "-o", "ControlPath=none",
    "-o", "ConnectTimeout=10",
]


def rsh(alias: str, script: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*SSH, alias, "bash -s"], input=script, capture_output=True, text=True, timeout=timeout
    )


@dataclass
class LinkStatus:
    reachable: bool = False
    hosts_ok: bool = False
    forward_ok: bool = False
    tunnel_ok: bool = False
    ca_ok: bool = False
    # something listens on :8000 (aiml-agents make server)
    agents_ok: bool = False
    # "" not running | "noca" running without the Twin CA | "ok"
    backend: str = ""
    # services (agentconnectors, ucvserver) that run without SSL_CERT_FILE at the Twin bundle
    no_ca: list = field(default_factory=list)
    # ~/co/aiml-agents/agent-platform exists
    agents_repo: bool = True
    # ~/co/backend exists
    backend_repo: bool = True
    # claude_core local.yaml sets sandbox_client.provider: local_docker
    sandbox_cfg: bool = False
    # aiml-agents started before local.yaml last changed
    sandbox_stale: bool = False
    # docker works for this user
    docker_ok: bool = False
    # local sandbox images are built
    sandbox_images: bool = False
    # local cloudserver on :3030 (serves /r/oauth/callback)
    cloudserver_ok: bool = False
    # dashboard dev server on :3000
    dashboard_ok: bool = False
    # vite runs with USE_VITE_DEVPROXY=true, so /r/ goes to the shared devproxy
    devproxy: bool = False
    # the :8000 server runs inside OwlAuth Twin's tmux (owltwin-run)
    agents_ours: bool = False
    # agentconnectorservice runs inside owltwin-run
    backend_ours: bool = False
    # the backend's Redis container (backend-redis-1) runs on :6380
    redis_backend: bool = False
    # aiml-agents' own Redis (redis7) runs, holding :6380
    redis_agents: bool = False
    # ~/co/aiml-agents/.envrc.local has LITELLM_API_KEY (from bin/setup.sh)
    agents_secrets: bool = False
    # aiml-agents started before .envrc.local last changed
    env_stale: bool = False
    # dynamodb-local answers and has the feature-flag-overrides table
    ddb_ok: bool = False
    # flags the org has a direct local override for
    overrides: set = field(default_factory=set)
    # owltwin-run window -> what runs in its pane (zsh = idle)
    windows: dict = field(default_factory=dict)
    # owltwin-run window -> last non-empty line
    tails: dict = field(default_factory=dict)
    # windows whose output shows an expired AWS SSO session
    sso: set = field(default_factory=set)
    # owltwin-run window -> last error-looking line
    errs: dict = field(default_factory=dict)
    # owltwin-run window -> taskrunner tasks shown as failed
    task_fails: dict = field(default_factory=dict)
    port443_owner: str = ""
    detail: str = ""

    @property
    def ready(self) -> bool:
        return (
            self.reachable and self.hosts_ok and self.forward_ok and self.tunnel_ok and self.ca_ok
        )


def status(alias: str, hosts: list[str], org: int = DEFAULT_ORG) -> LinkStatus:
    st = LinkStatus()
    script = f"""
set -u
for h in {' '.join(shlex.quote(h) for h in hosts)}; do grep -qE "^127\\.0\\.0\\.1 $h # {MARKER}$" /etc/hosts || echo "nohost $h"; done
owner=$(sudo -n ss -ltnpH 'sport = :443' 2>/dev/null | head -1)
echo "p443 $owner"
ss -ltnH 'sport = :{REMOTE_PORT}' | grep -q . && echo tunnel
test -s ~/.owltwin/combined-ca.pem && echo ca
ss -ltnH 'sport = :8000' | grep -q . && echo agents
for n in agentconnectors ucvserver; do
  pid=$(pgrep -x $n | head -1)
  if [ -n "$pid" ]; then
    if tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep -q '^SSL_CERT_FILE=.*\\.owltwin/combined-ca\\.pem$'; then echo "caok $n"; else echo "noca $n"; fi
  fi
done
test -d ~/co/aiml-agents/agent-platform || echo no_agents_repo
test -d ~/co/backend/.git || echo no_backend_repo
LY={LOCAL_YAML}
if [ -f "$LY" ] && grep -qE '^[[:space:]]*provider:[[:space:]]*"?local_docker"?[[:space:]]*$' "$LY"; then
  echo sbx_cfg
  apid=$(ss -ltnpH 'sport = :8000' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
  if [ -n "$apid" ]; then
    up=$(ps -o etimes= -p "$apid" 2>/dev/null | tr -d ' ')
    [ -n "$up" ] && [ $(( $(date +%s) - up )) -lt $(stat -c %Y "$LY") ] && echo sbx_stale
  fi
fi
# aiml-agents' dev secrets, written by its bin/setup.sh (populate_envrc.py); presence only, never the value.
EL={AGENTS_ENVRC}
if [ -f "$EL" ] && grep -qE '^export LITELLM_API_KEY=.+' "$EL"; then
  echo agt_secrets
  apid2=$(ss -ltnpH 'sport = :8000' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
  if [ -n "$apid2" ]; then
    up2=$(ps -o etimes= -p "$apid2" 2>/dev/null | tr -d ' ')
    [ -n "$up2" ] && [ $(( $(date +%s) - up2 )) -lt $(stat -c %Y "$EL") ] && echo env_stale
  fi
fi
docker info >/dev/null 2>&1 && echo docker
names=$(docker ps --format '{{{{.Names}}}}' 2>/dev/null)
printf '%s\\n' "$names" | grep -qx {REDIS_BACKEND} && echo redis_backend
printf '%s\\n' "$names" | grep -qx {REDIS_AGENTS} && echo redis_agents
docker image inspect {' '.join(SANDBOX_IMAGES)} >/dev/null 2>&1 && echo sbx_img
ss -ltnH 'sport = :3030' | grep -q . && echo cloudserver
ss -ltnH 'sport = :3000' | grep -q . && echo dashboard
for v in $(pgrep -f vite); do tr '\\0' '\\n' < /proc/$v/environ 2>/dev/null | grep -qx 'USE_VITE_DEVPROXY=true' && echo devproxy && break; done
true
""" + override_status(org) + RUN_STATUS  # noqa: E501
    try:
        r = rsh(alias, script, timeout=30)
    except subprocess.TimeoutExpired:
        st.detail = "ssh timed out"
        return st
    if r.returncode != 0 and not r.stdout:
        st.detail = (r.stderr or "ssh failed").strip().splitlines()[-1]
        return st
    st.reachable = True
    out = r.stdout.splitlines()
    st.hosts_ok = not any(line.startswith("nohost") for line in out)
    owner = next((line[5:] for line in out if line.startswith("p443 ")), "")
    st.port443_owner = owner.strip()
    st.forward_ok = "socat" in owner
    st.tunnel_ok = "tunnel" in out
    st.ca_ok = "ca" in out
    st.agents_ok = "agents" in out
    st.backend = (
        "ok" if "caok agentconnectors" in out else "noca" if "noca agentconnectors" in out else ""
    )
    st.no_ca = [line[5:] for line in out if line.startswith("noca ")]
    st.agents_repo = "no_agents_repo" not in out
    st.backend_repo = "no_backend_repo" not in out
    st.sandbox_cfg = "sbx_cfg" in out
    st.sandbox_stale = "sbx_stale" in out
    st.docker_ok = "docker" in out
    st.sandbox_images = "sbx_img" in out
    st.cloudserver_ok = "cloudserver" in out
    st.dashboard_ok = "dashboard" in out
    st.devproxy = "devproxy" in out
    st.agents_ours = "agents_ours" in out
    st.backend_ours = "backend_ours" in out
    st.redis_backend = "redis_backend" in out
    st.redis_agents = "redis_agents" in out
    st.ddb_ok = "ddb" in out
    st.agents_secrets = "agt_secrets" in out
    st.env_stale = "env_stale" in out
    for line in out:
        kind, _, rest = line.partition(" ")
        win, _, val = rest.partition(" ")
        if kind == "win" and win:
            st.windows[win] = val
        elif kind == "tail" and win:
            st.tails[win] = val
        elif kind == "tfail" and win:
            st.task_fails.setdefault(win, []).append(val)
        elif kind == "ovr" and win:
            st.overrides.add(win)
        elif kind == "sso" and win:
            st.sso.add(win)
        elif kind == "err" and win:
            st.errs[win] = val
    return st


def up(alias: str, hosts: list[str], ca_pem: str) -> str:
    """Installs hosts, CA bundle and the loopback forwarder. Returns '' or an error."""
    host_lines = "\\n".join(f"127.0.0.1 {h} # {MARKER}" for h in hosts)
    script = f"""
set -euo pipefail
mkdir -p ~/.owltwin
cat > ~/.owltwin/ca.pem <<'PEM'
{ca_pem.strip()}
PEM
cat /etc/ssl/certs/ca-certificates.crt ~/.owltwin/ca.pem > ~/.owltwin/combined-ca.pem
sudo -n sed -i '/# {MARKER}$/d' /etc/hosts
printf '{host_lines}\\n' | sudo -n tee -a /etc/hosts >/dev/null
owner=$(sudo -n ss -ltnpH 'sport = :443' | head -1 || true)
if [ -n "$owner" ] && ! echo "$owner" | grep -q socat; then echo "BUSY $owner"; exit 3; fi
if [ -z "$owner" ]; then
  tmux has-session -t =owltwin-fwd 2>/dev/null || tmux new-session -d -s owltwin-fwd -n forward
  tmux set-option -w -t owltwin-fwd:forward remain-on-exit on >/dev/null
  tmux respawn-pane -k -t owltwin-fwd:forward "sudo -n socat TCP-LISTEN:443,bind=127.0.0.1,reuseaddr,fork TCP:127.0.0.1:{REMOTE_PORT}"
fi
"""  # noqa: E501
    r = rsh(alias, script)
    if r.returncode == 3:
        owner = r.stdout.split("BUSY", 1)[-1].strip()
        return "Port 443 on the devbox is taken by another process: " + owner
    if r.returncode != 0:
        return (r.stderr or r.stdout or "setup failed").strip()[-400:]
    return ""


# Stops what OwlAuth Twin runs in owltwin-run (Ctrl+C first, so taskrunner and make server shut down
# cleanly), then removes the session. Docker containers they started stay, as after a normal Ctrl+C.
STOP_RUN = r"""
S=owltwin-run
if tmux has-session -t "=$S" 2>/dev/null; then
  desc() { for c in $(pgrep -P "$1"); do echo "$c"; desc "$c"; done; }
  BYPANE
  panes=$(tmux list-panes -s -t "=$S" -F '#{pane_id}')
  shells=$(tmux list-panes -s -t "=$S" -F '#{pane_pid}')
  # Collected while the panes exist; afterwards only checked for still being alive.
  found=$( { for p in $shells; do desc "$p"; done; for t in $panes; do bypane "$t"; done; } | sort -u | grep -vxF "$shells")
  all() { for p in $found; do [ -d /proc/$p ] && echo "$p"; done; }
  for t in $panes; do tmux send-keys -t "$t" C-c; done
  for i in $(seq 1 20); do [ -z "$(all)" ] && break; sleep 1; done
  k=$(all); [ -n "$k" ] && kill -TERM $k 2>/dev/null
  for i in $(seq 1 10); do [ -z "$(all)" ] && break; sleep 1; done
  k=$(all); [ -n "$k" ] && kill -KILL $k 2>/dev/null
  tmux kill-session -t "=$S" 2>/dev/null
fi
true
""".replace("BYPANE", BYPANE)  # noqa: E501


ROUTE_DOWN = f"""
sudo -n sed -i '/# {MARKER}$/d' /etc/hosts
tmux kill-session -t =owltwin-fwd 2>/dev/null || true
tmux kill-session -t =owltwin 2>/dev/null || true
"""


def route_down(alias: str) -> str:
    """Removes the hosts lines and the :443 forwarder. Leaves owltwin-run alone."""
    try:
        r = rsh(alias, ROUTE_DOWN + "true\n", timeout=30)
    except subprocess.TimeoutExpired:
        return "the devbox did not answer while removing the route"
    return "" if r.returncode == 0 else (r.stderr or "cleanup failed").strip()


def down(alias: str) -> str:
    """route_down, then stops what OwlAuth Twin runs in owltwin-run."""
    try:
        with _tmux_lock(alias):
            r = rsh(alias, ROUTE_DOWN + STOP_RUN, timeout=90)
    except subprocess.TimeoutExpired:
        return "the devbox did not answer while stopping owltwin-run"
    return "" if r.returncode == 0 else (r.stderr or "cleanup failed").strip()


class ReverseTunnel:
    """ssh -R with reconnect; stops when told to."""

    def __init__(self, alias: str, local_port: int):
        self.alias = alias
        self.local_port = local_port
        self.proc: subprocess.Popen[bytes] | None = None
        self.stopped = False
        self.connected_since = 0.0
        self.attempt = 0
        self.last_error = ""
        threading.Thread(target=self._loop, name="reverse-tunnel", daemon=True).start()

    def _loop(self) -> None:
        delay = 1.0
        while not self.stopped:
            self.attempt += 1
            cmd = [
                *SSH,
                "-o", "ExitOnForwardFailure=yes",
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=3",
                "-R", f"127.0.0.1:{REMOTE_PORT}:127.0.0.1:{self.local_port}",
                self.alias, TUNNEL_CMD,
            ]
            # stdin stays open, never written
            self.proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            started = time.time()
            self.connected_since = started
            # not communicate(): it closes stdin
            err = self.proc.stderr.read() if self.proc.stderr else b""
            self.proc.wait()
            self.connected_since = 0.0
            lines = (err or b"").decode("utf-8", "replace").strip().splitlines()
            self.last_error = lines[-1] if lines else ""
            if self.stopped:
                return
            delay = 1.0 if time.time() - started > 30 else min(delay * 2, 30.0)
            time.sleep(delay)

    @property
    def up(self) -> bool:
        return bool(self.connected_since) and time.time() - self.connected_since > 2

    def stop(self) -> None:
        self.stopped = True
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
