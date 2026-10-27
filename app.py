#!/usr/bin/env python3
"""ipcheck - tiny echo server: shows which client IP / headers the hosting proxy
passes to the app.  Standard library only (no pip install).

  /        human readable page (open it in a browser)
  /json    same data as JSON (used by ipcheck.py from Termux)
  /log     last 50 requests seen (compare browser vs Termux vs spoof tests)
"""
import json
import os
import sys
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("PORT", "7700"))
LOG = deque(maxlen=50)

IP_HEADERS = ["x-forwarded-for", "x-real-ip", "cf-connecting-ip", "true-client-ip",
              "x-client-ip", "forwarded", "x-forwarded-host", "x-forwarded-proto",
              "via", "cf-ray", "cf-ipcountry", "x-envoy-external-address"]


def snapshot(handler, tag=""):
    hdrs = [(k, v) for k, v in handler.headers.items()]      # keeps duplicates + order
    low = {}
    for k, v in hdrs:
        low.setdefault(k.lower(), []).append(v)
    xff_raw = ", ".join(low.get("x-forwarded-for", []))
    xff = [x.strip() for x in xff_raw.split(",") if x.strip()]
    peer = handler.client_address[0]
    cand = {
        "socket_peer": peer,
        "xff_first": xff[0] if xff else None,
        "xff_last": xff[-1] if xff else None,
        "x_real_ip": (low.get("x-real-ip") or [None])[0],
        "cf_connecting_ip": (low.get("cf-connecting-ip") or [None])[0],
        "true_client_ip": (low.get("true-client-ip") or [None])[0],
    }
    return {
        "time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "tag": tag,
        "method": handler.command,
        "path": handler.path,
        "socket_peer": peer,
        "xff_list": xff,
        "xff_count": len(xff),
        "candidates": cand,
        "ip_related_headers": {h: low[h] for h in IP_HEADERS if h in low},
        "all_headers": hdrs,
    }


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        pass

    def _out(self, body, ctype):
        b = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        tag = (qs.get("tag") or [""])[0][:40]
        if u.path == "/log":
            return self._out(json.dumps(list(LOG), indent=1), "application/json")
        snap = snapshot(self, tag)
        if u.path != "/favicon.ico":
            LOG.appendleft({k: snap[k] for k in ("time", "tag", "path", "socket_peer", "xff_list",
                                                 "ip_related_headers")})
            print(json.dumps({k: snap[k] for k in ("time", "tag", "socket_peer", "xff_list")}), flush=True)
        if u.path == "/json":
            return self._out(json.dumps(snap, indent=1), "application/json")
        lines = ["ipcheck - what the app sees", "=" * 40,
                 "socket peer (direct connection) : %s" % snap["socket_peer"],
                 "X-Forwarded-For list            : %s" % (snap["xff_list"] or "(none)"),
                 ""]
        for k, v in snap["candidates"].items():
            lines.append("%-18s %s" % (k, v))
        lines += ["", "ip related headers:"]
        for k, v in snap["ip_related_headers"].items():
            lines.append("  %s: %s" % (k, " | ".join(v)))
        lines += ["", "all headers:"] + ["  %s: %s" % kv for kv in snap["all_headers"]]
        self._out("\n".join(lines), "text/plain")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print("[ipcheck] listening on 0.0.0.0:%d" % PORT, flush=True)
    srv.serve_forever()
