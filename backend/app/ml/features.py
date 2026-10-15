"""Feature extraction shared by the training pipeline and the live scorer.

The order of features MUST stay identical between training and scoring,
otherwise the model silently sees a different input space.
"""

import math

COMMON_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 143, 443,
    3306, 5432, 6379, 8080, 8443, 9200, 27017,
}

PROTOCOL_ENCODING = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2,
    "DNS": 3,
    "HTTP": 4,
    "HTTPS": 5,
    "SSH": 6,
    "FTP": 7,
    "SMTP": 8,
    "OTHER": 9,
}


def _log1p(value) -> float:
    try:
        return math.log1p(max(0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def encode_protocol(protocol: str) -> float:
    return float(PROTOCOL_ENCODING.get((protocol or "OTHER").upper(), 9))


def is_unusual_port(port) -> float:
    try:
        return 0.0 if int(port) in COMMON_PORTS else 1.0
    except (TypeError, ValueError):
        return 1.0


def build_flow_features(
    *,
    source_port,
    destination_port,
    protocol,
    direction,
    bytes_transferred,
    packet_count,
    duration_ms,
    recent_flows_from_src=0,
) -> list:
    """Return the fixed-order feature vector for a network flow."""
    bytes_transferred = max(0, bytes_transferred or 0)
    packet_count = max(0, packet_count or 0)
    duration_ms = max(0, duration_ms or 0)

    bytes_per_packet = (
        bytes_transferred / packet_count if packet_count else 0.0
    )
    bytes_per_second = (
        bytes_transferred / (duration_ms / 1000.0) if duration_ms else 0.0
    )
    packet_rate = (
        packet_count / (duration_ms / 1000.0) if duration_ms else 0.0
    )

    return [
        _log1p(bytes_transferred),
        _log1p(packet_count),
        _log1p(duration_ms),
        _log1p(bytes_per_packet),
        _log1p(bytes_per_second),
        _log1p(packet_rate),
        _log1p(recent_flows_from_src),
        is_unusual_port(destination_port),
        encode_protocol(protocol),
        0.0 if (direction or "inbound").lower() == "inbound" else 1.0,
    ]