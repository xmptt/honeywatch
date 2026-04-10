#!/usr/bin/env python3
"""
RDP NLA test client — simulates a basic RDP client performing NLA/CredSSP
to test the honeypot's credential capture stack.

Usage:
    python3 test_rdp_nla.py
    python3 test_rdp_nla.py --host 127.0.0.1 --port 3389 --user testuser --password hunter2
"""

import socket
import ssl
import struct
import argparse

# ---------------------------------------------------------------------------
# X.224 Connection Request with NLA (PROTOCOL_HYBRID)
# ---------------------------------------------------------------------------

def build_x224_cr():
    """X.224 Connection Request selecting PROTOCOL_HYBRID (NLA)."""
    rdp_neg_req = struct.pack("<BBHI", 0x01, 0x00, 8, 0x03)  # type, flags, len, HYBRID|SSL
    payload = b"Cookie: mstshash=testuser\r\n" + rdp_neg_req
    li = 6 + len(payload)
    x224 = bytes([li, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + payload
    length = 4 + len(x224)
    tpkt = struct.pack(">BBH", 3, 0, length)
    return tpkt + x224


# ---------------------------------------------------------------------------
# Minimal ASN.1
# ---------------------------------------------------------------------------

def _len(n):
    if n < 0x80: return bytes([n])
    if n < 0x100: return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])

def _tag(t, d): return bytes([t]) + _len(len(d)) + d
def _seq(d):    return _tag(0x30, d)
def _ctx(n, d): return _tag(0xA0 + n, d)
def _oct(d):    return _tag(0x04, d)
def _int(n):    return _tag(0x02, bytes([n]))


def credssp_wrap(token: bytes) -> bytes:
    """Wrap raw NTLM token in a CredSSP TSRequest."""
    item = _seq(_ctx(0, _oct(token)))
    return _seq(_ctx(0, _int(6)) + _ctx(1, _seq(item)))


# ---------------------------------------------------------------------------
# NTLM NEGOTIATE (Type 1)
# ---------------------------------------------------------------------------

NTLM_SIG = b"NTLMSSP\x00"

def build_ntlm_negotiate(username="testuser", domain="WORKGROUP"):
    flags = (
        0x00000001   # UNICODE
        | 0x00000004 # REQUEST_TARGET
        | 0x00000200 # NTLM
        | 0x00008000 # ALWAYS_SIGN
        | 0x00080000 # IDENTIFY
        | 0x02000000 # VERSION
        | 0x20000000 # 128-bit
        | 0x40000000 # KEY_EXCH
        | 0x80000000 # 56-bit
    )
    return (
        NTLM_SIG
        + struct.pack("<I", 1)          # MessageType = NEGOTIATE
        + struct.pack("<I", flags)
        + struct.pack("<HHI", 0, 0, 0)  # DomainNameFields (empty)
        + struct.pack("<HHI", 0, 0, 0)  # WorkstationFields (empty)
        + bytes([0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F])  # Version
    )


# ---------------------------------------------------------------------------
# NTLM AUTHENTICATE (Type 3) — fake credentials
# ---------------------------------------------------------------------------

def build_ntlm_authenticate(username, domain, nt_response, server_challenge):
    """Build a minimal NTLM Type 3 AUTHENTICATE with fake NT response."""
    username_b = username.encode("utf-16-le")
    domain_b   = domain.encode("utf-16-le")
    workstation_b = b""
    lm_response   = b"\x00" * 24
    session_key   = b""

    flags = (
        0x00000001 | 0x00000004 | 0x00000200
        | 0x00008000 | 0x02000000 | 0x20000000
        | 0x40000000 | 0x80000000
    )

    # Field offsets (after fixed 72-byte header)
    base = 72
    lm_off   = base
    nt_off   = lm_off + len(lm_response)
    dom_off  = nt_off + len(nt_response)
    usr_off  = dom_off + len(domain_b)
    ws_off   = usr_off + len(username_b)
    key_off  = ws_off + len(workstation_b)

    def field(data, off):
        return struct.pack("<HHI", len(data), len(data), off)

    header = (
        NTLM_SIG
        + struct.pack("<I", 3)
        + field(lm_response, lm_off)
        + field(nt_response, nt_off)
        + field(domain_b,    dom_off)
        + field(username_b,  usr_off)
        + field(workstation_b, ws_off)
        + field(session_key, key_off)
        + struct.pack("<I", flags)
        + bytes([0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F])  # Version
    )
    payload = lm_response + nt_response + domain_b + username_b + workstation_b + session_key
    return header + payload


def fake_nt_response():
    """Return a plausible-looking but fake 24-byte NTLMv1 response."""
    import os
    return os.urandom(24)


# ---------------------------------------------------------------------------
# Read one CredSSP TSRequest from socket
# ---------------------------------------------------------------------------

def recv_msg(sock):
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) >= 4 and buf[0] == 0x30:
            if buf[1] < 0x80 and len(buf) >= 2 + buf[1]:
                return buf
            elif buf[1] == 0x81 and len(buf) >= 3 and len(buf) >= 3 + buf[2]:
                return buf
            elif buf[1] == 0x82 and len(buf) >= 4:
                total = 4 + (buf[2] << 8 | buf[3])
                if len(buf) >= total:
                    return buf
    return buf


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="RDP NLA test client")
    parser.add_argument("--host",     default="127.0.0.1")
    parser.add_argument("--port",     type=int, default=3389)
    parser.add_argument("--user",     default="testuser")
    parser.add_argument("--password", default="hunter2")
    parser.add_argument("--domain",   default="WORKGROUP")
    args = parser.parse_args()

    print(f"[*] Connecting to {args.host}:{args.port}")
    raw = socket.create_connection((args.host, args.port), timeout=10)

    # Step 1: X.224 Connection Request (select NLA)
    raw.sendall(build_x224_cr())
    cc = raw.recv(1024)
    print(f"[*] X.224 CC received ({len(cc)}b): {cc.hex()}")

    # Step 2: TLS upgrade (ignore cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    tls = ctx.wrap_socket(raw, server_hostname=args.host)
    print(f"[*] TLS handshake complete — cipher: {tls.cipher()[0]}")

    # Step 3: Send CredSSP TSRequest with NTLM NEGOTIATE
    negotiate = build_ntlm_negotiate(args.user, args.domain)
    tls.sendall(credssp_wrap(negotiate))
    print(f"[*] Sent NTLM NEGOTIATE")

    # Step 4: Receive NTLM CHALLENGE
    challenge_ts = recv_msg(tls)
    print(f"[*] Received challenge ({len(challenge_ts)}b)")
    ntlm_pos = challenge_ts.find(NTLM_SIG)
    if ntlm_pos == -1:
        print("[!] NTLM CHALLENGE not found in response — honeypot may have rejected us")
        return
    server_challenge = challenge_ts[ntlm_pos + 24: ntlm_pos + 32]
    print(f"[*] Server challenge: {server_challenge.hex()}")

    # Step 5: Send NTLM AUTHENTICATE with fake credentials
    nt_resp = fake_nt_response()
    authenticate = build_ntlm_authenticate(args.user, args.domain, nt_resp, server_challenge)
    tls.sendall(credssp_wrap(authenticate))
    print(f"[*] Sent NTLM AUTHENTICATE (user={args.user}, domain={args.domain})")
    print(f"[+] Done — check honeypot log for credential capture")


if __name__ == "__main__":
    main()
