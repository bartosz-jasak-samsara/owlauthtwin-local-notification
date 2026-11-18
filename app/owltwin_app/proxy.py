"""Tiny HTTP CONNECT proxy for Chrome. The PAC sends only the provider's
browser hosts here; anything else is refused, so nothing can leak to a real
vendor or to a host we did not list."""

from __future__ import annotations

import contextlib
import select
import socket
import socketserver
import threading
from collections.abc import Callable


class _Handler(socketserver.BaseRequestHandler):
    allowed: Callable[[], list[str]]
    target_port: Callable[[], int]

    def handle(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(10)
        try:
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    return
                head += chunk
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split()
            if len(parts) < 2 or parts[0] != "CONNECT":
                sock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                return
            host, _, port = parts[1].rpartition(":")
            host = host.strip("[]").lower()
            if port != "443" or host not in self.allowed():
                sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            upstream = socket.create_connection(("127.0.0.1", self.target_port()), timeout=10)
        except OSError:
            return
        sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        sock.settimeout(None)
        upstream.settimeout(None)
        self._pipe(sock, upstream)

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 300)
                if not r:
                    return
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            return
        finally:
            for s in (a, b):
                with contextlib.suppress(OSError):
                    s.close()


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_proxy(
    port: int, allowed: Callable[[], list[str]], target_port: Callable[[], int]
) -> _Server:
    attrs = {
        "allowed": staticmethod(allowed),
        "target_port": staticmethod(target_port),
    }
    handler = type("ProxyHandler", (_Handler,), attrs)
    srv = _Server(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, name="proxy", daemon=True).start()
    return srv


def pac_script(hosts: list[str], port: int) -> str:
    cond = " ||\n      ".join(f'host == "{h}"' for h in hosts) or "false"
    # No DIRECT fallback for Twin hosts: if owltwin is down they fail instead
    # of reaching the real vendor.
    return (
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        f"  if ({cond}) {{\n    return \"PROXY 127.0.0.1:{port}\";\n  }}\n"
        "  return \"DIRECT\";\n}\n"
    )
