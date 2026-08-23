import struct
from pathlib import Path

# Classic pcap magic numbers (same-endian / swapped, usec and nsec resolution). tcpdump -w on Ubuntu
# writes classic pcap by default; pcapng (0x0A0D0D0A magic) is not supported here — unrecognized magic
# just yields no packets rather than raising, since a capture file is effectively untrusted input.
_MAGICS = {0xA1B2C3D4: "<", 0xD4C3B2A1: ">", 0xA1B23C4D: "<", 0x4D3CB2A1: ">"}


def _iter_frames(path: Path):
    data = path.read_bytes()
    if len(data) < 24:
        return
    (magic,) = struct.unpack("<I", data[:4])
    order = _MAGICS.get(magic)
    if order is None:
        (magic,) = struct.unpack(">I", data[:4])
        order = _MAGICS.get(magic)
        if order is None:
            return
    offset = 24
    while offset + 16 <= len(data):
        try:
            _, _, incl_len, _ = struct.unpack(order + "IIII", data[offset : offset + 16])
        except struct.error:
            return
        offset += 16
        if offset + incl_len > len(data):
            return
        yield data[offset : offset + incl_len]
        offset += incl_len


def _parse_ipv4_tcp(frame: bytes):
    """Ethernet -> IPv4 -> TCP only (matches what the sandbox's docker0 bridge actually carries). Returns
    (src_ip, dst_ip, src_port, dst_port, payload) or None. IPv6/non-TCP frames are skipped, not an error."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    version_ihl = ip[0]
    ihl = (version_ihl & 0x0F) * 4
    protocol = ip[9]
    if protocol != 6 or len(ip) < ihl + 20:
        return None
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    src_port, dst_port = struct.unpack(">HH", tcp[0:4])
    data_offset = ((tcp[12] >> 4) & 0x0F) * 4
    payload = tcp[data_offset:]
    return src_ip, dst_ip, src_port, dst_port, payload


def _parse_udp(frame: bytes):
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:
        return None
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    udp = ip[ihl:]
    src_port, dst_port = struct.unpack(">HH", udp[0:4])
    return src_ip, dst_ip, src_port, dst_port, udp[8:]


def parse_client_hello_sni(payload: bytes) -> str | None:
    """TLS ClientHello SNI extension — plaintext on the wire (sent before any encryption is negotiated),
    so this needs no MITM/certificate injection, just a byte walk. Any malformed/short input returns None."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32  # handshake header(4) + client_version(2) + random(32)
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_suites_len = struct.unpack(">H", payload[pos : pos + 2])[0]
        pos += 2 + cipher_suites_len
        compression_len = payload[pos]
        pos += 1 + compression_len
        if pos + 2 > len(payload):
            return None
        extensions_len = struct.unpack(">H", payload[pos : pos + 2])[0]
        pos += 2
        end = pos + extensions_len
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", payload[pos : pos + 4])
            pos += 4
            if ext_type == 0x0000:  # server_name
                sni_pos = pos + 2 + 1  # server_name_list_len(2) + name_type(1)
                name_len = struct.unpack(">H", payload[sni_pos : sni_pos + 2])[0]
                sni_pos += 2
                return payload[sni_pos : sni_pos + name_len].decode("ascii", errors="replace")
            pos += ext_len
    except (struct.error, IndexError):
        return None
    return None


def extract_sni_records(pcap_path: Path) -> list[dict]:
    records = []
    for frame in _iter_frames(pcap_path):
        parsed = _parse_ipv4_tcp(frame)
        if parsed is None:
            continue
        src_ip, dst_ip, src_port, dst_port, payload = parsed
        sni = parse_client_hello_sni(payload)
        if sni:
            records.append({"src": src_ip, "dst": dst_ip, "dst_port": dst_port, "sni": sni})
    return records


def _decode_dns_name(msg: bytes, pos: int) -> tuple[str, int]:
    labels = []
    while True:
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer, not followed further (name not needed past here)
            pos += 2
            break
        pos += 1
        labels.append(msg[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels), pos


def extract_dns_answers(pcap_path: Path) -> dict[str, list[str]]:
    """domain -> resolved A-record IPs, parsed from DNS response packets in the capture. Used to check
    whether a ClientHello's SNI actually matches the IP that was looked up for it."""
    answers: dict[str, list[str]] = {}
    for frame in _iter_frames(pcap_path):
        parsed = _parse_udp(frame)
        if parsed is None:
            continue
        _, _, src_port, _, msg = parsed
        if src_port != 53 or len(msg) < 12:
            continue
        try:
            flags, qdcount, ancount = struct.unpack(">HHH", msg[2:8])
            if not (flags & 0x8000) or ancount == 0:  # QR bit: only responses carry answers
                continue
            pos = 12
            for _ in range(qdcount):
                _, pos = _decode_dns_name(msg, pos)
                pos += 4  # qtype + qclass
            for _ in range(ancount):
                name, pos = _decode_dns_name(msg, pos)
                rtype, _, _, rdlength = struct.unpack(">HHIH", msg[pos : pos + 10])
                pos += 10
                if rtype == 1 and rdlength == 4:  # A record
                    ip = ".".join(str(b) for b in msg[pos : pos + 4])
                    answers.setdefault(name.rstrip("."), []).append(ip)
                pos += rdlength
        except (struct.error, IndexError):
            continue
    return answers


def sni_mismatches(sni_records: list[dict], dns_answers: dict[str, list[str]]) -> list[dict]:
    mismatches = []
    for record in sni_records:
        known_ips = dns_answers.get(record["sni"])
        if known_ips is None:
            continue  # no DNS answer observed for this hostname -> unverifiable, not a mismatch
        if record["dst"] not in known_ips:
            mismatches.append({**record, "resolved_ips": known_ips})
    return mismatches
