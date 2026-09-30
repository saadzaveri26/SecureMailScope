"""PCAP / PCAPNG ingestion -> normalised TCP packet records (pure Python, dpkt; no tshark needed)."""
from __future__ import annotations
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path

import dpkt

DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_RAW2, DLT_LOOP, DLT_LINUX_SLL, DLT_LINUX_SLL2 = 0, 1, 101, 12, 108, 113, 276
PCAP_MAGICS = {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class InvalidCapture(ValueError):
    pass


@dataclass(slots=True)
class TcpPacket:
    idx: int
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes
    wire_len: int


@dataclass
class PcapStats:
    total_packets: int = 0
    tcp_packets: int = 0
    non_tcp_packets: int = 0
    malformed_packets: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    linktype: int | None = None
    file_format: str = "pcap"
    warnings: list = field(default_factory=list)


def sniff_format(path: Path) -> str | None:
    with open(path, "rb") as f:
        m = f.read(4)
    if m in PCAP_MAGICS:
        return "pcap"
    if m == PCAPNG_MAGIC:
        return "pcapng"
    return None


def _l3(linktype: int, buf: bytes):
    if linktype == DLT_EN10MB:
        return dpkt.ethernet.Ethernet(buf).data
    if linktype in (DLT_RAW, DLT_RAW2):
        return dpkt.ip.IP(buf) if (buf[0] >> 4) == 4 else dpkt.ip6.IP6(buf)
    if linktype == DLT_LINUX_SLL:
        return dpkt.sll.SLL(buf).data
    if linktype == DLT_LINUX_SLL2 and hasattr(dpkt, "sll2"):
        return dpkt.sll2.SLL2(buf).data
    if linktype in (DLT_NULL, DLT_LOOP):
        return dpkt.loopback.Loopback(buf).data
    raise ValueError(f"unsupported link type {linktype}")


def read_tcp_packets(path: Path) -> tuple[list[TcpPacket], PcapStats]:
    fmt = sniff_format(path)
    if fmt is None:
        raise InvalidCapture("File is not a PCAP/PCAPNG capture (bad magic bytes)")
    stats = PcapStats(file_format=fmt)
    packets: list[TcpPacket] = []
    with open(path, "rb") as fp:
        try:
            reader = dpkt.pcapng.Reader(fp) if fmt == "pcapng" else dpkt.pcap.Reader(fp)
        except Exception as e:  # noqa: BLE001
            raise InvalidCapture(f"cannot open capture: {e}") from e
        try:
            linktype = reader.datalink()
        except Exception:  # noqa: BLE001
            linktype = DLT_EN10MB
        stats.linktype = linktype
        try:
            for ts, buf in reader:
                stats.total_packets += 1
                if stats.first_ts is None:
                    stats.first_ts = ts
                stats.last_ts = ts
                try:
                    ip = _l3(linktype, buf)
                except Exception:  # noqa: BLE001
                    stats.malformed_packets += 1
                    continue
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    stats.non_tcp_packets += 1
                    continue
                if isinstance(ip, dpkt.ip.IP) and (ip.mf or ip.offset):
                    stats.non_tcp_packets += 1        # fragmented IP not reassembled
                    continue
                tcp = ip.data
                if not isinstance(tcp, dpkt.tcp.TCP):
                    stats.non_tcp_packets += 1
                    continue
                fam = socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6
                packets.append(TcpPacket(
                    idx=stats.total_packets, ts=float(ts),
                    src=socket.inet_ntop(fam, ip.src), sport=tcp.sport,
                    dst=socket.inet_ntop(fam, ip.dst), dport=tcp.dport,
                    seq=tcp.seq, ack=tcp.ack, flags=tcp.flags, payload=bytes(tcp.data), wire_len=len(buf)))
                stats.tcp_packets += 1
        except (dpkt.NeedData, dpkt.UnpackError, struct.error, ValueError) as e:
            stats.warnings.append(f"capture truncated or corrupt after packet {stats.total_packets}: {e}")
    packets.sort(key=lambda p: (p.ts, p.idx))
    return packets, stats
