"""Local CA and server certificate for the Twin.

The CA lives only in owltwin's state folder. It is never added to the macOS
keychain; the devbox backend trusts it through SSL_CERT_FILE, and Chrome is
told to proceed with `thisisunsafe`.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def _run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True)


def ensure_certs(cert_dir: Path, hosts: list[str]) -> tuple[Path, Path, Path]:
    """Returns (ca.pem, server.pem, server-key.pem).

    Reissues the server cert when hosts change.
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = cert_dir / "ca-key.pem"
    ca = cert_dir / "ca.pem"
    key = cert_dir / "server-key.pem"
    crt = cert_dir / "server.pem"
    stamp = cert_dir / "hosts.sha"
    if not ca.exists():
        _run(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825",
            "-keyout", str(ca_key), "-out", str(ca),
            "-subj", "/CN=OwlAuth Twin Local CA (dev only)",
        )
        ca_key.chmod(0o600)
    names = sorted(set(hosts) | {"localhost"})
    want = hashlib.sha256("\n".join(names).encode()).hexdigest()
    if crt.exists() and stamp.exists() and stamp.read_text() == want:
        return ca, crt, key
    cnf = cert_dir / "san.cnf"
    lines = [
        "[req]", "distinguished_name=dn", "req_extensions=v3", "prompt=no",
        "[dn]", "CN=owltwin",
        "[v3]", "basicConstraints=CA:FALSE", "keyUsage=digitalSignature,keyEncipherment",
        "extendedKeyUsage=serverAuth", "subjectAltName=@alt",
        "[alt]",
    ]
    lines += [f"DNS.{i}={h}" for i, h in enumerate(names, 1)]
    lines += ["IP.1=127.0.0.1", "IP.2=::1"]
    cnf.write_text("\n".join(lines) + "\n")
    csr = cert_dir / "server.csr"
    _run(
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-config", str(cnf),
    )
    _run(
        "openssl", "x509", "-req", "-in", str(csr),
        "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(crt), "-days", "397", "-extensions", "v3", "-extfile", str(cnf),
    )
    key.chmod(0o600)
    stamp.write_text(want)
    return ca, crt, key
