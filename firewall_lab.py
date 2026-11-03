"""firewall-lab: a UFW rule builder and dry-run simulator.

Standard library only. Nothing in this module touches the host firewall:
it parses rules, evaluates traffic against them, and renders the
equivalent ``ufw`` commands as plain text for review.

Rules file format (one rule per line, ``#`` starts a comment):

    allow in  tcp 22        from any
    deny  in  tcp 23        from any
    allow in  tcp 8000-8100 from 192.168.1.0/24
    allow out udp 53        from any
    default-policy in deny
    default-policy out allow

Fields: action (allow|deny), direction (in|out), protocol
(tcp|udp|any), port (single port, a ``low-high`` range, or ``any``),
and an optional source (``any`` or an IP / CIDR block). Rules are
evaluated top to bottom; the FIRST matching rule wins, exactly like
a real firewall's ordered rule list. If no rule matches, the default
policy for that direction applies.

Traffic file format (one packet per line):

    192.168.1.10 22 tcp in
    10.0.0.5 443 tcp in
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    action: str       # "allow" | "deny"
    direction: str    # "in" | "out"
    protocol: str     # "tcp" | "udp" | "any"
    port_low: int     # 0 when port is "any"
    port_high: int    # 65535 when port is "any"
    source: str       # "any" or an IP / CIDR string

    def matches(self, src_ip: str, dst_port: int, protocol: str,
                direction: str) -> bool:
        if self.direction != direction:
            return False
        if self.protocol != "any" and self.protocol != protocol:
            return False
        if not (self.port_low <= dst_port <= self.port_high):
            return False
        if self.source == "any":
            return True
        try:
            network = ipaddress.ip_network(self.source, strict=False)
            return ipaddress.ip_address(src_ip) in network
        except ValueError:
            # A malformed source in a hand-written rules file should
            # never match silently; treat it as no match.
            return False

    def to_ufw(self) -> str:
        """Render the equivalent ``ufw`` command as text (not executed)."""
        if self.port_low == 0 and self.port_high == 65535:
            port_part = ""
        elif self.port_low == self.port_high:
            port_part = f" to any port {self.port_low}"
        else:
            port_part = f" to any port {self.port_low}:{self.port_high}"
        proto_part = "" if self.protocol == "any" else f" proto {self.protocol}"
        src_part = "any" if self.source == "any" else self.source
        return (f"ufw {self.action} {self.direction} from {src_part}"
                f"{proto_part}{port_part}").strip()


@dataclass(frozen=True)
class Packet:
    src_ip: str
    dst_port: int
    protocol: str
    direction: str


@dataclass(frozen=True)
class Verdict:
    packet: Packet
    outcome: str          # "allow" | "deny"
    matched_rule: Rule | None
    defaulted: bool       # True when no rule matched


def parse_port(text: str) -> tuple[int, int]:
    if text == "any":
        return 0, 65535
    if "-" in text:
        low, high = text.split("-", 1)
        low_i, high_i = int(low), int(high)
        if not (0 <= low_i <= high_i <= 65535):
            raise ValueError(f"invalid port range: {text!r}")
        return low_i, high_i
    port = int(text)
    if not (0 <= port <= 65535):
        raise ValueError(f"invalid port: {text!r}")
    return port, port


_RULE_RE = re.compile(
    r"^(allow|deny)\s+(in|out)\s+(tcp|udp|any)\s+(\S+)"
    r"(?:\s+from\s+(\S+))?\s*$")


def parse_rules(text: str) -> tuple[list[Rule], dict[str, str]]:
    """Parse a rules file. Returns (rules, default_policies).

    Defaults start as deny/in, allow/out (the common UFW-style setup)
    and can be overridden with ``default-policy in|out allow|deny`` lines.
    """
    rules: list[Rule] = []
    defaults = {"in": "deny", "out": "allow"}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("default-policy"):
            parts = line.split()
            if len(parts) != 3 or parts[1] not in ("in", "out") \
                    or parts[2] not in ("allow", "deny"):
                raise ValueError(
                    f"line {lineno}: bad default-policy line: {raw!r}")
            defaults[parts[1]] = parts[2]
            continue
        m = _RULE_RE.match(line)
        if not m:
            raise ValueError(f"line {lineno}: cannot parse rule: {raw!r}")
        action, direction, protocol, port_text, source = m.groups()
        low, high = parse_port(port_text)
        rules.append(Rule(action, direction, protocol, low, high,
                          source or "any"))
    return rules, defaults


def parse_traffic(text: str) -> list[Packet]:
    packets: list[Packet] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 4:
            raise ValueError(
                f"line {lineno}: expected 'src_ip port protocol direction', "
                f"got: {raw!r}")
        src_ip, port_text, protocol, direction = parts
        ipaddress.ip_address(src_ip)  # validates, raises ValueError if bad
        if protocol not in ("tcp", "udp"):
            raise ValueError(f"line {lineno}: bad protocol: {protocol!r}")
        if direction not in ("in", "out"):
            raise ValueError(f"line {lineno}: bad direction: {direction!r}")
        packets.append(Packet(src_ip, int(port_text), protocol, direction))
    return packets


def evaluate(packet: Packet, rules: list[Rule],
             defaults: dict[str, str]) -> Verdict:
    for rule in rules:
        if rule.matches(packet.src_ip, packet.dst_port,
                        packet.protocol, packet.direction):
            return Verdict(packet, rule.action, rule, False)
    return Verdict(packet, defaults[packet.direction], None, True)


def simulate(packets: list[Packet], rules: list[Rule],
             defaults: dict[str, str]) -> list[Verdict]:
    return [evaluate(p, rules, defaults) for p in packets]


def format_verdict(v: Verdict) -> str:
    p = v.packet
    if v.defaulted:
        why = f"default policy ({v.outcome})"
    else:
        r = v.matched_rule
        why = (f"matched rule: {r.action} {r.direction} {r.protocol} "
               f"{r.port_low if r.port_low == r.port_high else f'{r.port_low}-{r.port_high}'}"
               f" from {r.source}")
    return (f"{p.src_ip} -> port {p.dst_port}/{p.protocol} {p.direction}: "
            f"{v.outcome.upper()} ({why})")
