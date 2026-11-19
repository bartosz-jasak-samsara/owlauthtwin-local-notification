# OwlAuth Twin — Overview

> **Summary:** Routing **localdev** (Mac Chrome + Devbox backend) to local vendor mocks under **real production vendor domains** (`auth.monday.com`, `mcp.monday.com`, `accounts.google.com`, `mcp.atlassian.com`) with **zero code changes in Samsara**.

---

## 1. Why It Was Built — The Localdev Pain Points

- **Tests don't show the real UX or cross-service picture:** Most OAuth and MCP flows can be simulated in automated tests, but tests don't reflect the real end-to-end user experience we expose users to—and it isn't always easy to understand how all the underlying services connect together.
- **Real vendor accounts & callback access:** Testing real integrations requires vendor accounts + admin access to register local callback URLs (`/r/oauth/callback`), and you still cannot trigger edge cases (expired tokens, rotated secrets, revoked grants) on demand.
- **Different devboxes, different ports:** Samsara Dashboard runs on `:3000`, `:13000`, `:23000`, etc. Localdev computes `redirect_uri` from `DEVBOX_INDEX * 10000` (often unset/wrong), breaking the OAuth redirect back to Chrome.
- **Localdev port & env traps:** `USE_VITE_DEVPROXY=true` sends callbacks to shared staging `devproxy`; `aiml-agents` steals Redis `:6380` from the backend; `claude_core` defaults to mocked `e2b` instead of `local_docker` and hangs without `LITELLM_API_KEY` or `DD_DOGSTATSD_DISABLE_FORK_SUPPORT=1`.
- **Slow, fragile setup on fresh devboxes:** Bootstrapping 2 repos (`backend` + `aiml-agents`), `direnv allow`, `bin/setup.sh`, exact services, AWS SSO, and DynamoDB flag overrides takes too many manual steps—even an agent rarely gets it right on the first try.

---

## 2. Core Idea: Two Traffic Paths + One Local TLS Model

- **Real domains, zero Samsara changes:** Both Chrome and the Devbox backend keep calling real vendor URLs.
- **One Mac process serves all defined providers:** Two modes—**Full stack** (provisions & runs everything in tmux `owltwin-run`) or **Twin only** (routing + CA only).

```mermaid
flowchart TB
  subgraph Mac["Mac (Workstation)"]
    direction TB
    ChromeDash["Chrome: Samsara Dashboard\nhttps://localhost:<port>"]
    ChromeOAuth["Chrome: Real Vendor Domain\ne.g. https://auth.monday.com/..."]
    PAC["PAC /owltwin.pac\n127.0.0.1:18200"]
    Proxy["HTTP CONNECT Proxy\n127.0.0.1:18201"]
    TwinB["Twin Browser Listener\n127.0.0.1:<free_port> (TLS)"]
    TwinS["Twin Server Listener\n127.0.0.1:18443 (TLS)"]

    ChromeOAuth -- "1. PAC lookup" --> PAC
    ChromeOAuth -- "2. CONNECT real_host:443" --> Proxy
    Proxy -- "3. raw TCP pipe" --> TwinB
    TwinB -- "4. 302 callback port fix" --> ChromeDash
  end

  subgraph Tunnels["SSH Tunnels"]
    direction TB
    DevConnect["devbox connect\n:<port> -> :3000"]
    RevSSH["ReverseTunnel (ssh -R)\ndevbox :18443 -> Mac :18443"]
  end

  subgraph Devbox["Devbox (Samsara Localdev)"]
    direction TB
    Dashboard["Vite :3000 + cloudserver :3030\n(/r/oauth/callback)"]
    Backend["ucvserver + agentconnectors\n+ notification ingest + inbox worker\nSSL_CERT_FILE=~/.owltwin/combined-ca.pem"]
    Hosts["/etc/hosts (# OWLTWIN)\nreal vendor hosts -> 127.0.0.1"]
    Socat["socat (tmux owltwin-fwd)\n127.0.0.1:443 -> 127.0.0.1:18443"]

    Dashboard --- Backend
    Backend -- "HTTPS :443 to real vendor domain" --> Hosts
    Hosts --> Socat
  end

  ChromeDash --> DevConnect --> Dashboard
  Socat --> RevSSH --> TwinS
```

**Quick key to terms in this diagram:**
- **PAC:** macOS JS proxy rule—steers *only* Twin `browser_hosts` to `:18201`; `localhost` & everything else go `DIRECT`.
- **HTTP `CONNECT` Proxy (`:18201`):** Raw TCP tunnel for allowlisted `browser_hosts` (`:443`); never decrypts TLS.
- **`socat` (`:443 -> :18443`):** Root forwarder on the Devbox bridging `:443` to the unprivileged SSH tunnel port.
- **`ReverseTunnel` (`ssh -R`):** Forwards Devbox `:18443` back to the Twin Server Listener (`:18443`) on the Mac.
- **`combined-ca.pem`:** System CA roots + Twin CA so backends trust the Twin *and* real AWS/LaunchDarkly/LiteLLM.

---

## 3. Part 1 — Mac Browser Path (PAC + HTTP `CONNECT`)

```mermaid
flowchart TD
  Start["Chrome navigates to URL"] --> PAC{"PAC: FindProxyForURL\n127.0.0.1:18200/owltwin.pac"}
  PAC -- "localhost / Okta / anything else" --> Direct["DIRECT"]
  PAC -- "host in active browser_hosts\ne.g. auth.monday.com" --> Proxy["PROXY 127.0.0.1:18201\n(no DIRECT = fail-closed)"]
  Proxy --> AllowCheck{"CONNECT :443 &\nin _browser_hosts()?"}
  AllowCheck -- "No" --> Reject["403 / 405"]
  AllowCheck -- "Yes" --> Pipe["200 Connection Established\nTCP pipe -> Twin Browser Listener"]
  Pipe --> TLS["Direct TLS handshake\nChrome <-> Twin (SAN = real domain)"]
```

**Key points:**
- **Why PAC instead of Mac `/etc/hosts`?** No `sudo`, leaves non-browser processes alone, and lets us toggle Google/MS domains dynamically (`?v=<timestamp>` busts cache).
- **Fail-closed:** No `DIRECT` fallback for Twin hosts—if OwlAuth Twin stops, Chrome errors locally instead of hitting production vendors.
- **Time-boxed `idp_hosts`:** Okta/Zscaler/Samsara are always blocked (`owltwin lint`). Google/Microsoft hosts route to the Twin in Chrome *only* while **Intercept sign-in** is ON (max 10 min or until first token exchange).
- **Callback port fix:** Reads Chrome's real port from `Referer` on `/authorize` and redirects Chrome to `localhost:<port>/r/oauth/callback`, while `/token` still validates the backend's original `redirect_uri`.

---

## 4. Part 2 — Devbox Backend Path (`/etc/hosts` + `socat` + `ssh -R`)

```mermaid
flowchart TD
  App["ucvserver / agentconnectors\ncalls https://mcp.monday.com/mcp (:443)"] --> EtcHosts["/etc/hosts\n127.0.0.1 mcp.monday.com # OWLTWIN"]
  EtcHosts --> Loop443["Devbox 127.0.0.1:443\nsocat (root, tmux owltwin-fwd)"]
  Loop443 --> TunnelRemote["Devbox 127.0.0.1:18443\nssh -R ReverseTunnel"]
  TunnelRemote --> MacPort["Mac 127.0.0.1:18443\nTwin Server Listener (TLS)"]
```

**Key points:**
- **Tagged `/etc/hosts`:** Entries end with `# OWLTWIN`, so `Stop` removes only Twin lines.
- **Why `socat`?** Backends always dial `:443`, which unprivileged `ssh -R` cannot bind. `socat` bridges `127.0.0.1:443 -> 127.0.0.1:18443` (and aborts safely if another process owns `:443`).
- **`ReverseTunnel` extras:** Keepalive + auto-reconnect + symlinks `$SSH_AUTH_SOCK` to `~/.owltwin/agent.sock` so `git` works inside `owltwin-run`.

---

## 5. Part 3 — TLS & Certificates (Mac vs Devbox)

```mermaid
flowchart TB
  subgraph CertGen["1. Generated on Mac (~/.local/state/owltwin/certs/)"]
    CA["ca.pem + ca-key.pem (reused, 825d)"]
    SAN["server.pem (SAN = all_hosts + localhost)\nReissued when hosts.sha changes"]
    CA -->|signs| SAN
  end

  subgraph MacTrust["2A. Mac (Chrome)"]
    Chrome["Chrome gets server.pem\n(SAN matches real vendor domain)"]
    Bypass["CA NEVER added to macOS Keychain\nType 'thisisunsafe' once per host"]
    Chrome --> Bypass
  end

  subgraph DevboxTrust["2B. Devbox (Backend)"]
    Bundle["~/.owltwin/combined-ca.pem\n= system CAs + Twin ca.pem"]
    EnvVar["Per-process: SSL_CERT_FILE=~/.owltwin/combined-ca.pem\nReal AWS / LaunchDarkly / LiteLLM keep working"]
    Bundle --> EnvVar
  end

  SAN --> Chrome
  CA -. "copied to ~/.owltwin/ca.pem" .-> Bundle
```

**Key points:**
- **Mac stays clean:** Never touches macOS Keychain (`thisisunsafe` is scoped to Chrome only).
- **Why `combined-ca.pem`?** Twin CA alone would break outbound TLS to AWS, LaunchDarkly, and LiteLLM; `SSL_CERT_FILE` scopes trust per-process without altering OS trust stores.
- **Runtime detection:** `status()` checks `/proc/$pid/environ` on `ucvserver` / `agentconnectors` and flags missing CA (offering **Take over** in Full stack); `combined-ca.pem` stays after Stop so manual backends don't break.

---

## 6. Part 4 — End-to-End Flow (`monday.com` DCR Example)

```mermaid
sequenceDiagram
  autonumber
  participant C as Chrome (Mac)
  participant D as Samsara Dashboard / cloudserver (:3030)
  participant B as Backend (ucvserver / agentconnectors)
  participant TB as Twin Browser (:free_port)
  participant TS as Twin Server (:18443)

  Note over B,TS: Devbox path: /etc/hosts -> socat :443 -> ssh -R :18443
  D->>B: Click "Connect" in Samsara Dashboard
  B->>TS: GET https://mcp.monday.com/.well-known/oauth-protected-resource/mcp (RFC 9728)
  TS-->>B: resource + authorization_servers
  B->>TS: GET https://auth.monday.com/.well-known/oauth-authorization-server/mcp (RFC 8414)
  TS-->>B: authorize, token, register, auth_methods
  B->>TS: POST https://auth.monday.com/mcp/register (DCR RFC 7591)
  TS-->>B: client_id + client_secret (registers_as: client_secret_post)

  B-->>C: Redirect to https://auth.monday.com/mcp/authorize (state + PKCE S256 + resource)
  Note over C,TB: Mac path: PAC -> CONNECT :18201 -> Twin Browser
  C->>TB: GET https://auth.monday.com/mcp/authorize (Referer = localhost:<port>)
  TB-->>C: Consent page -> Allow
  TB-->>C: 302 -> https://localhost:<port>/r/oauth/callback?code=...&state=...

  C->>D: GET /r/oauth/callback?code=...&state=...
  D->>B: Forward code + state
  B->>TS: POST https://auth.monday.com/mcp/token (code + code_verifier + resource)
  TS-->>B: access_token + refresh_token

  B->>TS: POST https://mcp.monday.com/mcp (Bearer: initialize / tools/list / tools/call)
  TS-->>B: Mock tool response from providers/monday.yaml
```

**Key points:**
- **All defined providers run at once:** `TwinRegistry.route()` disambiguates shared hosts (e.g., Google, Atlassian) by: `listener/host` → `endpoint` → `client_id` → `issued token` → `Authorization scheme (Basic vs Bearer)` → panel fallback (`ambiguous`).
- **One-click fault injection:** *Expire access token* (`401`), *Rotate secret* (`invalid_client`), *Revoke tokens* (`400 invalid_grant`).

---

## 7. Modes, Safety & Cleanup (Quick Summary)

- **`Full stack` vs `Twin only`:** Full stack provisions `backend` + `aiml-agents`, sets `local_docker` sandbox, frees Redis `:6380`, opens AWS SSO in Chrome, sets `USE_VITE_DEVPROXY=false`, starts local `notificationeventingestionservice` + `inboxnotificationworker`, and writes `dynamodb-local` (`:8768`) flag overrides. Twin only sets up routing + CA and monitors your own services.
- **Safety:** Loopback-only (`127.0.0.1`), `owltwin lint` blocks `okta.com` / `zscaler.net` / `samsara.com` + wildcards, panel enforces `local_only` (DNS rebinding guard), never kills user processes without **Take over**.
- **Stop vs `Ctrl+C`:** `Stop` restores PAC from `proxy-saved.json`, kills `ssh -R`, removes `# OWLTWIN` hosts, stops `owltwin-fwd` / `owltwin-run`. `Ctrl+C` runs the same cleanup while keeping `session.json` (12h) for **Continue last session**.

---

## 8. Glossary

| Term | Short Explanation |
|---|---|
| **PAC (`owltwin.pac`)** | JS `FindProxyForURL` script registered via `networksetup`; routes only `browser_hosts` to `:18201`, everything else `DIRECT`. |
| **HTTP `CONNECT` Proxy** | TCP tunnel (`CONNECT host:443`) on `:18201`; forwards raw encrypted bytes to Twin without terminating TLS. |
| **Fail-closed** | PAC has no `DIRECT` fallback for Twin hosts—if OwlAuth Twin is down, requests fail instead of hitting real vendors. |
| **`ssh -R` / `socat`** | `ssh -R` forwards Devbox `:18443` -> Mac `:18443`; root `socat` bridges Devbox `:443` -> `:18443`. |
| **`agent.sock`** | Symlink kept alive by `ReverseTunnel` so `tmux` panes keep a working `SSH_AUTH_SOCK` for `git`. |
| **SAN (`hosts.sha`)** | Multi-domain X.509 extension listing all defined vendor hosts in one `server.pem` (auto-reissued on host changes). |
| **`combined-ca.pem` / `SSL_CERT_FILE`** | System CAs + Twin CA injected per-process so Devbox backends trust Twin *and* real AWS/LaunchDarkly/LiteLLM. |
| **`thisisunsafe`** | Chrome interstitial bypass passphrase—lets Chrome trust Twin locally without touching macOS Keychain. |
| **DCR (RFC 7591) & `registers_as`** | Dynamic `POST /register`; `registers_as` reproduces vendors that upgrade public `none` requests to `client_secret_post`. |
| **RFC 9728 / 8414 / 8707 / PKCE** | Protected-resource & auth-server discovery, `resource` token binding, and `S256` code challenge verification. |
| **`USE_VITE_DEVPROXY=false`** | Keeps `/r/oauth/callback` on local `cloudserver :3030` instead of shared staging `devproxy`. |
| **`dynamodb-local` overrides** | Writes `ORGFLAGS#<org>` rows on `:8768` so dev orgs get `agent-studio-enabled` / `credits-experience-enabled`. |
