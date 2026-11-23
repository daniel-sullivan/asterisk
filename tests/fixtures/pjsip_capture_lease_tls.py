#!/usr/bin/env python3
"""Exercise the compiled logger; run inside the Asterisk builder with --network none."""

from pathlib import Path
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import time


def configure(root):
    conf = root / "asterisk.conf"
    conf.write_text(
        "[directories]\n"
        + "".join(f"{key} = {root}\n" for key in (
            "astetcdir", "astvarlibdir", "astdbdir", "astspooldir", "astlogdir", "astrundir",
        ))
        + "astmoddir = /usr/lib/asterisk/modules\n"
    )
    (root / "modules.conf").write_text(
        "[modules]\nautoload = no\n"
        + "".join(f"require = {module}.so\n" for module in (
            "res_pjproject", "res_sorcery_config", "res_sorcery_memory",
            "res_sorcery_astdb", "res_pjsip", "res_pjsip_logger",
        ))
    )
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-keyout", str(root / "key.pem"),
         "-out", str(root / "cert.pem")],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    (root / "pjsip.conf").write_text(
        "[global]\ntype=global\ndebug=no\n\n"
        "[isolated-tls]\ntype=transport\nprotocol=tls\nmethod=tlsv1_2\nbind=127.0.0.1:5061\n"
        f"cert_file={root / 'cert.pem'}\npriv_key_file={root / 'key.pem'}\n"
    )
    return conf


def response(code, reason, method, call_id):
    return (
        f"SIP/2.0 {code} {reason}\r\n"
        f"Via: SIP/2.0/TLS 127.0.0.1:5061;branch=z9hG4bK{call_id}\r\n"
        "From: <sip:fixture@localhost>;tag=from\r\n"
        "To: <sip:fixture@localhost>;tag=to\r\n"
        f"Call-ID: {call_id}\r\nCSeq: 1 {method}\r\nContent-Length: 0\r\n\r\n"
    ).encode()


def verify(root, conf, process):
    def cli(command):
        reply = subprocess.check_output(
            ["asterisk", "-C", str(conf), "-rx", command], text=True, stderr=subprocess.DEVNULL,
        )
        # In a network-none container the CLI prints a local EID warning on stdout.
        lines = [line for line in reply.splitlines() if line.startswith("PJSIP capture ")]
        assert len(lines) == 1, reply
        return lines[0]

    startup_deadline = time.monotonic() + 20
    while True:
        if process.poll() is not None or time.monotonic() >= startup_deadline:
            raise RuntimeError("isolated Asterisk TLS listener did not become ready")
        try:
            sock = socket.create_connection(("127.0.0.1", 5061), timeout=2)
            break
        except OSError:
            time.sleep(0.1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.load_verify_locations(cafile=str(root / "cert.pem"))
    pcap = root / "proof.pcap"
    disabled = "PJSIP capture off; normal logger off"
    rejected = response(503, "Service Unavailable", "INVITE", "fixture-rejected")
    accepted = response(200, "OK", "INVITE", "fixture-accepted")

    def send(conn, message, expected):
        with conn, context.wrap_socket(conn, server_hostname="localhost") as tls:
            size_before = pcap.stat().st_size
            tls.sendall(message)
            until = time.monotonic() + 3
            while time.monotonic() < until:
                payload = pcap.read_bytes()
                if expected in payload[size_before:]:
                    print(f"PCAP grew from {size_before} to {len(payload)} bytes", flush=True)
                    return
                time.sleep(0.05)
            raise AssertionError(
                f"Final INVITE response missing after TLS send; PCAP bytes {size_before} -> {pcap.stat().st_size}"
            )

    status = cli("pjsip capture lease status")
    assert status == disabled, status
    deadline_ms = time.time_ns() // 1_000_000 + 5_000
    prepared = cli(f"pjsip capture lease prepare {deadline_ms}")
    assert prepared.startswith("PJSIP capture prepared "), prepared
    nonce = prepared.split()[-1]
    started = cli(f"pjsip capture lease start {nonce} {pcap} 127.0.0.1/32")
    assert started == f"PJSIP capture started {nonce}", started
    assert stat.S_IMODE(pcap.stat().st_mode) == 0o600
    excluded = response(200, "OK", "OPTIONS", "fixture-excluded")
    # Both orientations matter: an ineligible message can precede or follow an INVITE.
    send(sock, rejected + excluded + accepted, accepted)
    payload = pcap.read_bytes()
    offset = 24  # PCAP global header.
    for sip in (rejected, accepted):
        _, _, incl_len, orig_len = struct.unpack_from("=IIII", payload, offset)
        offset += 16
        assert incl_len == orig_len == 14 + 20 + 8 + len(sip)
        assert payload[offset + 42:offset + incl_len] == sip
        offset += incl_len
    assert offset == len(payload), "unexpected extra packet or trailing bytes"
    assert excluded not in payload

    def wait_for_deadline(deadline):
        time.sleep(max(0, (deadline - time.time_ns() // 1_000_000) / 1000) + 0.05)

    # Keep the active lease unobserved by CLI/timer until after the late packet.
    wait_for_deadline(deadline_ms)
    with socket.create_connection(("127.0.0.1", 5061), timeout=2) as conn:
        with context.wrap_socket(conn, server_hostname="localhost") as tls:
            tls.sendall(response(503, "Service Unavailable", "INVITE", "fixture-after-expiry"))
            time.sleep(0.1)
    assert pcap.read_bytes() == payload, "expired capture wrote another packet"
    assert cli("pjsip capture lease status") == disabled

    late_pcap = root / "late.pcap"
    deadline_ms = time.time_ns() // 1_000_000 + 1_000
    prepared = cli(f"pjsip capture lease prepare {deadline_ms}")
    assert prepared.startswith("PJSIP capture prepared "), prepared
    late_nonce = prepared.split()[-1]
    wait_for_deadline(deadline_ms)
    assert cli(f"pjsip capture lease start {late_nonce} {late_pcap} 127.0.0.1/32").startswith(
        "PJSIP capture refused:"
    )
    assert not late_pcap.exists()
    assert cli("pjsip capture lease status") == disabled


def main():
    with tempfile.TemporaryDirectory(prefix="asterisk-lease-fixture-") as tmp:
        root = Path(tmp)
        conf = configure(root)
        log_path = root / "asterisk.log"
        with log_path.open("w") as log:
            process = subprocess.Popen(
                ["asterisk", "-C", str(conf), "-f", "-n"],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                verify(root, conf, process)
            except Exception:
                print(log_path.read_text())
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    print("ok: exact coalesced TLS INVITE 503/200; OPTIONS and expired packet absent; late start refused")


if __name__ == "__main__":
    main()
