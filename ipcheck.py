#!/usr/bin/env python3
"""Run in Termux:   python3 ipcheck.py https://YOUR-APP.blitz.cloud
Optional:          python3 ipcheck.py https://YOUR-APP.blitz.cloud 1.2.3.4   (your real public IP)
Standard library only.  Sends a normal request, then ONE fake header at a time,
and tells which IP header of the hosting proxy can be trusted."""
import json
import sys
import urllib.error
import urllib.request

FAKE = "9.9.9.9"
HEADERS = ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"]


def get(url, headers=None):
    """-> (http_status, data_or_None). Never raises for HTTP errors."""
    req = urllib.request.Request(url, headers=dict({"User-Agent": "ipcheck/1"}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        print("   network error:", e)
        return 0, None


def my_public_ip():
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "curl/8"}), timeout=10) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return ""


def val(d, h):
    v = d["ip_related_headers"].get(h.lower())
    return v[0] if v else None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    base = sys.argv[1].rstrip("/")
    me = sys.argv[2] if len(sys.argv) > 2 else my_public_ip()
    print("your public IP (from ipify):", me or "UNKNOWN (pass it as 2nd argument)")

    st, d0 = get(base + "/json?tag=termux-normal")
    if not d0:
        print("normal request failed, HTTP", st)
        return
    print("\n--- 1. normal request (HTTP %s)" % st)
    print("  socket peer :", d0["socket_peer"], "(proxy/internal address)")
    print("  XFF list    :", d0["xff_list"] or "(none)")
    for h in HEADERS[1:]:
        print("  %-17s:" % h, val(d0, h))

    print("\n--- 2. fake IP %s, one header at a time" % FAKE)
    safe = []
    for h in HEADERS:
        st, d = get(base + "/json?tag=termux-fake-" + h.lower(), {h: FAKE})
        if d is None:
            print("  %-17s -> BLOCKED by the platform (HTTP %s)  [good: fake never reaches the app]" % (h, st))
            continue
        lst = d["xff_list"] if h == "X-Forwarded-For" else [val(d, h)]
        if FAKE in lst:
            pos = "FIRST" if lst[0] == FAKE else ("LAST" if lst[-1] == FAKE else "MIDDLE")
            print("  %-17s -> fake PASSED THROUGH (%s of %d)  list=%s" % (h, pos, len(lst), lst))
            if h == "X-Forwarded-For" and lst[-1] != FAKE and me and lst[-1] == me:
                safe.append("X-Forwarded-For: use the LAST entry (proxy appends the real IP)")
        else:
            print("  %-17s -> fake removed/overwritten, app sees %s" % (h, lst))
            if me and (val(d0, h) == me or (h == "X-Forwarded-For" and d0["xff_list"][:1] == [me])):
                safe.append(h)

    print("\n================ RESULT ================")
    if me:
        print("normal request: " + ", ".join("%s=%s" % (h, "OK" if (val(d0, h) == me) else val(d0, h))
                                               for h in HEADERS[1:]))
    print("SAFE TO TRUST:", ", ".join(safe) if safe else "none found - send me this whole output")


if __name__ == "__main__":
    main()
