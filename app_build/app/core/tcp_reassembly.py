"""TCP flow tracking and per-direction byte-stream reassembly (handles retransmission, reordering, wrap)."""
from __future__ import annotations
from bisect import bisect_right
from dataclasses import dataclass

from ..config import MAIL_PORTS
from .pcap_reader import TcpPacket

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
M32 = 0xFFFFFFFF


class DirectionStream:
    def __init__(self, ip: str, port: int):
        self.ip, self.port = ip, port
        self.segments: list[tuple[int, float, bytes]] = []
        self.isn: int | None = None
        self.packets = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.fin = False
        self.rst = False
        self.data = b""
        self.retransmissions = 0
        self.gaps = 0
        self._offs: list[int] = []
        self._ts: list[float] = []

    def add(self, p: TcpPacket) -> None:
        self.packets += 1
        self.first_ts = p.ts if self.first_ts is None else self.first_ts
        self.last_ts = p.ts
        if p.flags & SYN:
            self.isn = p.seq
        self.fin |= bool(p.flags & FIN)
        self.rst |= bool(p.flags & RST)
        if p.payload:
            self.segments.append((p.seq, p.ts, p.payload))
            self.bytes += len(p.payload)

    def reassemble(self) -> None:
        if not self.segments:
            return
        base = ((self.isn + 1) & M32) if self.isn is not None else self.segments[0][0]
        rel = [(((seq - base + 2 ** 31) & M32) - 2 ** 31, ts, pl) for seq, ts, pl in self.segments]
        lo = min(r[0] for r in rel)
        rel = sorted(((o - lo, ts, pl) for o, ts, pl in rel), key=lambda r: (r[0], r[1]))
        out = bytearray()
        nxt = rel[0][0]
        for off, ts, pl in rel:
            end = off + len(pl)
            if end <= nxt:
                self.retransmissions += 1
                continue
            if off > nxt:
                self.gaps += 1
                nxt = off
            chunk = pl[nxt - off:] if off < nxt else pl
            self._offs.append(len(out))
            self._ts.append(ts)
            out += chunk
            nxt = end
        self.data = bytes(out)

    def ts_at(self, offset: int) -> float | None:
        if not self._offs:
            return self.first_ts
        return self._ts[max(bisect_right(self._offs, offset) - 1, 0)]


class TcpFlow:
    def __init__(self, stream_id: int, first: TcpPacket):
        self.stream_id = stream_id
        self.packets: list[TcpPacket] = [first]
        self.has_data = False
        self.fins: set = set()
        self.rst = False
        self.syn_seqs: set = set()
        self.client = self.server = None
        self.c2s: DirectionStream | None = None
        self.s2c: DirectionStream | None = None
        self.rtt: float | None = None

    def add(self, p: TcpPacket) -> None:
        if p is not self.packets[0]:
            self.packets.append(p)
        if p.payload:
            self.has_data = True
        if p.flags & FIN:
            self.fins.add((p.src, p.sport))
        if p.flags & RST:
            self.rst = True
        if p.flags & SYN and not p.flags & ACK:
            self.syn_seqs.add(p.seq)

    @property
    def closed(self) -> bool:
        return self.rst or len(self.fins) >= 2

    def finalize(self) -> None:
        syn = next((p for p in self.packets if p.flags & SYN and not p.flags & ACK), None)
        synack = next((p for p in self.packets if p.flags & SYN and p.flags & ACK), None)
        first = self.packets[0]
        if syn:
            client, server = (syn.src, syn.sport), (syn.dst, syn.dport)
        elif synack:
            server, client = (synack.src, synack.sport), (synack.dst, synack.dport)
        else:
            a, b = (first.src, first.sport), (first.dst, first.dport)
            if b[1] in MAIL_PORTS and a[1] not in MAIL_PORTS:
                client, server = a, b
            elif a[1] in MAIL_PORTS and b[1] not in MAIL_PORTS:
                client, server = b, a
            else:
                client, server = (a, b) if a[1] > b[1] else (b, a)
        self.client, self.server = client, server
        self.c2s, self.s2c = DirectionStream(*client), DirectionStream(*server)
        for p in self.packets:
            (self.c2s if (p.src, p.sport) == client else self.s2c).add(p)
        self.c2s.reassemble()
        self.s2c.reassemble()
        if syn and synack:
            self.rtt = max(synack.ts - syn.ts, 0.0)

    @property
    def start_ts(self) -> float:
        return self.packets[0].ts

    @property
    def end_ts(self) -> float:
        return self.packets[-1].ts

    @property
    def termination(self) -> str:
        return "RST" if self.rst else ("FIN" if self.fins else "open")


def build_flows(packets: list[TcpPacket]) -> list[TcpFlow]:
    flows: list[TcpFlow] = []
    active: dict = {}
    for p in packets:
        key = frozenset(((p.src, p.sport), (p.dst, p.dport)))
        f = active.get(key)
        is_syn = bool(p.flags & SYN) and not p.flags & ACK
        if f is not None and is_syn and (f.has_data or f.closed) and p.seq not in f.syn_seqs:
            f = None                                     # port re-use -> new stream
        if f is None:
            f = TcpFlow(len(flows), p)
            flows.append(f)
            active[key] = f
        f.add(p)
    for f in flows:
        f.finalize()
    return flows
