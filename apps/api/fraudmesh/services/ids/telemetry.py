"""Zeek / Suricata telemetry normalisation.

FraudMesh *consumes* IDS telemetry; it does not capture packets. Accepted inputs:

* Zeek JSON logs (``LogAscii::use_json=T``): conn, dns, http, ssl, notice
* Suricata EVE JSON: alert, flow, dns, http, tls

Each record becomes a ``NetObservation`` (metadata only — no payload inspection;
TLS is described by handshake metadata such as SNI and JA3, never decrypted).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class NetObservation:
    sensor: str  # zeek | suricata
    log_type: str  # conn | dns | http | ssl | notice | alert | flow
    ts: datetime
    uid: str | None
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    proto: str | None
    service: str | None = None
    duration: float | None = None
    bytes_out: int | None = None
    bytes_in: int | None = None
    pkts_out: int | None = None
    pkts_in: int | None = None
    conn_state: str | None = None
    dns_query: str | None = None
    dns_rcode: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    http_status: int | None = None
    http_user_agent: str | None = None
    tls_sni: str | None = None
    tls_ja3: str | None = None
    tls_validation: str | None = None
    signature: str | None = None
    signature_id: int | None = None
    signature_severity: int | None = None
    signature_category: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return {k: v for k, v in d.items() if v is not None and v != {}}


class TelemetryError(ValueError):
    pass


def _ts(v: Any) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(float(v), tz=timezone.utc)
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
    raise TelemetryError("missing timestamp")


def _int(v: Any) -> int | None:
    try:
        return int(v) if v not in (None, "-", "") else None
    except (TypeError, ValueError):
        return None


def _float(v: Any) -> float | None:
    try:
        return float(v) if v not in (None, "-", "") else None
    except (TypeError, ValueError):
        return None


def parse_zeek(log_type: str, rec: dict) -> NetObservation:
    try:
        base = dict(
            sensor="zeek", log_type=log_type, ts=_ts(rec["ts"]), uid=rec.get("uid"),
            src_ip=rec["id.orig_h"], src_port=_int(rec.get("id.orig_p")),
            dst_ip=rec["id.resp_h"], dst_port=_int(rec.get("id.resp_p")), proto=rec.get("proto"),
        )
    except KeyError as exc:
        raise TelemetryError(f"zeek {log_type} record missing field {exc}") from exc
    if log_type == "conn":
        return NetObservation(**base, service=rec.get("service"), duration=_float(rec.get("duration")),
                              bytes_out=_int(rec.get("orig_bytes")), bytes_in=_int(rec.get("resp_bytes")),
                              pkts_out=_int(rec.get("orig_pkts")), pkts_in=_int(rec.get("resp_pkts")),
                              conn_state=rec.get("conn_state"))
    if log_type == "dns":
        return NetObservation(**base, service="dns", dns_query=rec.get("query"), dns_rcode=rec.get("rcode_name"))
    if log_type == "http":
        return NetObservation(**base, service="http", http_method=rec.get("method"), http_host=rec.get("host"),
                              http_uri=rec.get("uri"), http_status=_int(rec.get("status_code")),
                              http_user_agent=rec.get("user_agent"))
    if log_type == "ssl":
        return NetObservation(**base, service="ssl", tls_sni=rec.get("server_name"), tls_ja3=rec.get("ja3"),
                              tls_validation=rec.get("validation_status"))
    if log_type == "notice":
        return NetObservation(**base, signature=rec.get("note"), signature_category="zeek-notice",
                              extra={"msg": rec.get("msg")})
    raise TelemetryError(f"unsupported zeek log type {log_type}")


def parse_suricata(rec: dict) -> NetObservation:
    et = rec.get("event_type")
    try:
        base = dict(
            sensor="suricata", log_type=et, ts=_ts(rec["timestamp"]), uid=str(rec.get("flow_id")) if rec.get("flow_id") else None,
            src_ip=rec["src_ip"], src_port=_int(rec.get("src_port")), dst_ip=rec["dest_ip"], dst_port=_int(rec.get("dest_port")),
            proto=(rec.get("proto") or "").lower() or None,
        )
    except KeyError as exc:
        raise TelemetryError(f"suricata record missing field {exc}") from exc
    if et == "alert":
        a = rec.get("alert") or {}
        return NetObservation(**base, signature=a.get("signature"), signature_id=_int(a.get("signature_id")),
                              signature_severity=_int(a.get("severity")), signature_category=a.get("category"),
                              http_host=(rec.get("http") or {}).get("hostname"), tls_sni=(rec.get("tls") or {}).get("sni"))
    if et == "flow":
        f = rec.get("flow") or {}
        return NetObservation(**base, bytes_out=_int(f.get("bytes_toserver")), bytes_in=_int(f.get("bytes_toclient")),
                              pkts_out=_int(f.get("pkts_toserver")), pkts_in=_int(f.get("pkts_toclient")),
                              conn_state=f.get("state"))
    if et == "dns":
        d = rec.get("dns") or {}
        return NetObservation(**base, service="dns", dns_query=d.get("rrname"), dns_rcode=d.get("rcode"))
    if et == "http":
        h = rec.get("http") or {}
        return NetObservation(**base, service="http", http_method=h.get("http_method"), http_host=h.get("hostname"),
                              http_uri=h.get("url"), http_status=_int(h.get("status")), http_user_agent=h.get("http_user_agent"))
    if et == "tls":
        t = rec.get("tls") or {}
        return NetObservation(**base, service="ssl", tls_sni=t.get("sni"), tls_ja3=(t.get("ja3") or {}).get("hash"))
    raise TelemetryError(f"unsupported suricata event_type {et}")


def parse(record: dict, sensor: str | None = None, log_type: str | None = None) -> NetObservation:
    if sensor == "suricata" or "event_type" in record:
        return parse_suricata(record)
    lt = log_type or record.get("_path") or record.get("log_type")
    if not lt:
        raise TelemetryError("zeek record needs log_type (or _path)")
    return parse_zeek(lt, record)
