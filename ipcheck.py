#!/usr/bin/env python3
"""Run in Termux:   python3 ipcheck.py https://YOUR-APP.blitz.cloud
Optional:          python3 ipcheck.py https://YOUR-APP.blitz.cloud 1.2.3.4   (your real public IP)
Standard library only.  Sends normal + fake-header requests and tells which IP
header/position of the hosting proxy can be trusted."""
import json
import sys
import urllib.request

FAKE = "9.9.9.9"


def get(url, headers=None):
    req = urllib.request.Request(url, headers=dict({"User-Agent": "ipcheck/1"}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())


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


def show(title, d):
    print("\n--- %s" % title)
    print("  socket peer :", d["socket_peer"])
    print("  XFF list    :", d["xff_list"] or "(none)")
    for k, v in d["ip_related_headers"].items():
        if k != "x-forwarded-for":
            print("  %-12s:" % k, " | ".join(v))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    base = sys.argv[1].rstrip("/")
    me = sys.argv[2] if len(sys.argv) > 2 else my_public_ip()
    print("your public IP (from ipify):", me or "UNKNOWN (pass it as 2nd argument)")

    base_d = get(base + "/json?tag=termux-normal")
    show("1. normal request", base_d)
    spoof = {
        "X-Forwarded-For": FAKE,
        "X-Real-IP": FAKE,
        "CF-Connecting-IP": FAKE,
        "True-Client-IP": FAKE,
    }
    sp = get(base + "/json?tag=termux-spoof", spoof)
    show("2. request WITH fake headers (%s)" % FAKE, sp)

    print("\n================ RESULT ================")
    l1, l2 = base_d["xff_list"], sp["xff_list"]
    rec = None
    if me:
        if me in l1:
            pos1 = "FIRST" if l1[0] == me else ("LAST" if l1[-1] == me else "MIDDLE")
            print("normal: your IP is in X-Forwarded-For (%s of %d)" % (pos1, len(l1)))
        else:
            print("normal: your IP is NOT in X-Forwarded-For")
        for h in ("x-real-ip", "cf-connecting-ip", "true-client-ip"):
            v = base_d["ip_related_headers"].get(h)
            if v:
                print("normal: %s = %s %s" % (h, v[0], "(= your IP)" if v[0] == me else "(not your IP)"))
        print("normal: socket peer = %s %s" % (base_d["socket_peer"],
              "(= your IP, no proxy hides it)" if base_d["socket_peer"] == me else "(proxy address)"))
    fake_in = FAKE in l2
    fake_pos = None
    if fake_in:
        fake_pos = "FIRST" if l2[0] == FAKE else ("LAST" if l2[-1] == FAKE else "MIDDLE")
    print("spoof : fake IP in X-Forwarded-For: %s" % ("YES (%s of %d)" % (fake_pos, len(l2)) if fake_in else "NO (proxy removed/overwrote it)"))
    for h in ("x-real-ip", "cf-connecting-ip", "true-client-ip"):
        v = sp["ip_related_headers"].get(h)
        if v:
            print("spoof : %s = %s %s" % (h, v[0], "<- FAKE passed through, do NOT trust" if v[0] == FAKE else "<- real (proxy overwrote the fake)"))

    if me:
        if fake_in and l2[-1] != FAKE and me in l2:
            rec = "TRUST the LAST entry of X-Forwarded-For (proxy appends; the first one is client-controlled)."
        elif not fake_in and me in l2:
            rec = "X-Forwarded-For is safe: proxy overwrites it. Use the first entry."
        elif fake_in and l2[-1] == FAKE:
            rec = "UNSAFE: fake IP is last in X-Forwarded-For. Look at the other headers/socket peer."
        for h in ("x-real-ip", "cf-connecting-ip", "true-client-ip"):
            v1 = base_d["ip_related_headers"].get(h)
            v2 = sp["ip_related_headers"].get(h)
            if v1 and v1[0] == me and v2 and v2[0] != FAKE:
                rec = (rec + "\n" if rec else "") + "ALSO SAFE: header %s (real IP, fake overwritten)." % h
    print("\nRECOMMENDATION:", rec or "could not decide - send me the output above (and the /log page).")


if __name__ == "__main__":
    main()
