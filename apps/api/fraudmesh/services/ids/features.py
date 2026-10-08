"""Flow features for the network anomaly model (shared by training and serving)."""

from __future__ import annotations

import math

CONN_STATES = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTR": 3, "RSTOS0": 3, "SH": 4, "OTH": 4, "S1": 0, "established": 0, "closed": 0, "new": 1}
FLOW_FEATURES = ["log_bytes_out", "log_bytes_in", "log_duration", "log_pkts_out", "log_pkts_in", "out_in_ratio", "port_class", "state_class", "is_udp"]


def port_class(port: int | None) -> int:
    if port in (443, 80, 8443):
        return 0
    if port == 53:
        return 1
    if port is not None and port < 1024:
        return 2
    return 3


def flow_vector(bytes_out, bytes_in, duration, pkts_out, pkts_in, dst_port, conn_state, proto) -> list[float]:
    bo, bi = float(bytes_out or 0), float(bytes_in or 0)
    return [
        math.log1p(bo),
        math.log1p(bi),
        math.log1p(float(duration or 0.0) * 1000),
        math.log1p(float(pkts_out or 0)),
        math.log1p(float(pkts_in or 0)),
        math.log1p(bo) - math.log1p(bi),
        float(port_class(dst_port)),
        float(CONN_STATES.get(conn_state or "OTH", 4)),
        1.0 if (proto or "").lower() == "udp" else 0.0,
    ]
