"""Network / IDS detector.

Layers (each produces explainable findings):

1. **Signatures** – Suricata alerts and Zeek notices passed through with their severity.
2. **Threat intelligence** – IP reputation, JA3 fingerprints, domains, user agents.
3. **Frequency / pattern analysis** – Redis 5-minute windows per source IP:
   port scanning, brute force / credential stuffing on auth endpoints, NXDOMAIN
   bursts (DGA malware), outbound volume (exfiltration).
4. **Anomaly model** – Isolation Forest over flow metadata (conn/flow records).

Risk = noisy-OR of finding severities, so independent indicators compound while a
single weak one stays weak.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time

import joblib
import numpy as np

from fraudmesh.config import get_settings
from fraudmesh.core.redis import redis
from fraudmesh.detection.base import BaseDetector, DetectorResult, DetectorStatus, Reason
from fraudmesh.services.ids import intel
from fraudmesh.services.ids.features import flow_vector
from fraudmesh.services.ids.telemetry import NetObservation
from fraudmesh.services.metrics.telemetry import telemetry

WINDOW_S = 300
PORTSCAN_DISTINCT_PORTS = 15
AUTH_FAILURES = 8
NXDOMAIN_BURST = 10
EXFIL_BYTES = 200 * 1024 * 1024
SEVERITY = {1: 0.9, 2: 0.65, 3: 0.4, 4: 0.25}


def _finding(kind: str, fid: str, title: str, severity: float, detail: str, technique: str | None = None) -> dict:
    return {"kind": kind, "id": fid, "title": title, "severity": round(float(severity), 3), "detail": detail, "mitre": technique}


class NetworkDetector(BaseDetector):
    name = "ids"
    domain = "network"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded = False
        self.model = None
        self.card: dict = {}
        self.error: str | None = None

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            d = get_settings().artifact_dir / "ids"
            try:
                self.card = json.loads((d / "model_card.json").read_text())
                path = d / self.card["artifact"]
                if hashlib.sha256(path.read_bytes()).hexdigest() != self.card["artifact_sha256"]:
                    raise ValueError("model artifact checksum mismatch")
                self.model = joblib.load(path)
                self._q = np.array(self.card["score_mapping"]["quantiles"])
            except Exception as exc:
                self.error = f"{type(exc).__name__}: {exc}"
            self._loaded = True

    @property
    def model_version(self) -> str:
        self._load()
        return f"ids-rules-v1+{self.card.get('version', 'no-anomaly-model')}"

    def status(self) -> DetectorStatus:
        self._load()
        state = "ONLINE" if self.model is not None else "DEGRADED"  # rules still run without the model
        return DetectorStatus(self.name, self.domain, state, self.model_version, "Signatures + intel + windows + Isolation Forest", self.error or "")

    async def _window(self, obs: NetObservation) -> list[dict]:
        findings: list[dict] = []
        bucket = int(obs.ts.timestamp() // WINDOW_S)
        r = redis()
        src = obs.src_ip
        pipe = r.pipeline()
        keys: list[str] = []
        if obs.dst_port is not None and obs.log_type in ("conn", "flow") and obs.conn_state in ("S0", "REJ", "RSTO", "RSTOS0", "SH", "new"):
            k = f"ids:ports:{src}:{bucket}"
            pipe.sadd(k, obs.dst_port)
            pipe.scard(k)
            keys.append(("ports", k))
        if obs.http_status in (401, 403) and intel.is_auth_endpoint(obs.http_uri):
            k = f"ids:authfail:{src}:{bucket}"
            pipe.incr(k)
            keys.append(("authfail", k))
        if obs.dns_rcode and obs.dns_rcode.upper() == "NXDOMAIN":
            k = f"ids:nx:{src}:{bucket}"
            pipe.incr(k)
            keys.append(("nx", k))
        if obs.bytes_out:
            k = f"ids:out:{src}:{bucket}"
            pipe.incrby(k, int(obs.bytes_out))
            keys.append(("out", k))
        if not keys:
            return findings
        for _, k in keys:
            pipe.expire(k, WINDOW_S * 2)
        res = await pipe.execute()
        i = 0
        for kind, _ in keys:
            if kind == "ports":
                count = res[i + 1]
                i += 2
                if count >= PORTSCAN_DISTINCT_PORTS:
                    findings.append(_finding("pattern", "PORT_SCAN", "Port scanning", min(0.95, 0.6 + count / 100),
                                             f"{count} distinct destination ports probed from {src} in 5 min", "T1046"))
            else:
                val = res[i]
                i += 1
                if kind == "authfail" and val >= AUTH_FAILURES:
                    findings.append(_finding("pattern", "CREDENTIAL_STUFFING", "Credential stuffing / brute force on login endpoint",
                                             min(0.95, 0.6 + val / 60), f"{val} failed authentications from {src} in 5 min", "T1110.004"))
                elif kind == "nx" and val >= NXDOMAIN_BURST:
                    findings.append(_finding("pattern", "NXDOMAIN_BURST", "NXDOMAIN burst (possible DGA malware)", 0.7,
                                             f"{val} failed DNS lookups in 5 min", "T1568.002"))
                elif kind == "out" and val >= EXFIL_BYTES:
                    findings.append(_finding("pattern", "ABNORMAL_OUTBOUND", "Abnormal outbound volume (possible exfiltration)", 0.75,
                                             f"{val / 1e6:.0f} MB sent by {src} in 5 min", "T1041"))
        return findings

    async def analyze(self, obs: NetObservation) -> DetectorResult:
        self._load()
        t = time.perf_counter()
        findings: list[dict] = []

        if obs.signature:
            sev = SEVERITY.get(obs.signature_severity or 3, 0.4)
            findings.append(_finding("signature", f"SIG_{obs.signature_id or 'NOTICE'}", obs.signature, sev,
                                     f"{obs.sensor} {obs.signature_category or ''}".strip()))

        rep_src = intel.ip_reputation(obs.src_ip)
        rep_dst = intel.ip_reputation(obs.dst_ip)
        for side, ip, rep in (("source", obs.src_ip, rep_src), ("destination", obs.dst_ip, rep_dst)):
            if rep["risk"] >= 0.5:
                findings.append(_finding("reputation", f"IP_{rep['category'].upper()}", f"{side.title()} IP flagged: {rep['category'].replace('_', ' ')}",
                                         rep["risk"], f"{ip} ({rep['source']})"))
        if (j := intel.ja3(obs.tls_ja3)) is not None:
            findings.append(_finding("intel", "JA3_MATCH", "Known-bad TLS client fingerprint (JA3)", j["risk"], j["label"], "T1071.001"))
        for host in (obs.dns_query, obs.http_host, obs.tls_sni):
            if (d := intel.domain(host)) is not None:
                findings.append(_finding("intel", "DOMAIN_MATCH", "Connection to known-malicious domain", d["risk"], f"{host}: {d['label']}", "T1566"))
                break
        if (u := intel.user_agent(obs.http_user_agent)) is not None:
            sev = u["risk"] + (0.2 if intel.is_auth_endpoint(obs.http_uri) else 0.0)
            findings.append(_finding("intel", "SUSPICIOUS_UA", f"Suspicious user agent: {u['label']}", min(0.95, sev),
                                     f"{obs.http_user_agent} → {obs.http_uri or ''}"))
        if obs.dns_query and (dga := intel.dga_score(obs.dns_query)) >= 0.5:
            findings.append(_finding("pattern", "DGA_DOMAIN", "Algorithmically generated / tunnelling-like domain", 0.4 + 0.5 * dga,
                                     f"{obs.dns_query} (score {dga:.2f})", "T1568.002"))
        if obs.tls_validation and obs.tls_validation.lower() not in ("ok", "") and intel.is_protected_domain(obs.tls_sni):
            findings.append(_finding("pattern", "TLS_INTERCEPTION", "Invalid certificate for protected banking domain", 0.8,
                                     f"{obs.tls_sni}: {obs.tls_validation}", "T1557"))

        findings += await self._window(obs)

        anomaly_pct = None
        if self.model is not None and obs.log_type in ("conn", "flow"):
            v = np.array([flow_vector(obs.bytes_out, obs.bytes_in, obs.duration, obs.pkts_out, obs.pkts_in, obs.dst_port, obs.conn_state, obs.proto)])
            raw = float(-self.model.score_samples(v)[0])
            anomaly_pct = float(np.searchsorted(self._q, raw) / len(self._q))
            if anomaly_pct >= 0.99:
                findings.append(_finding("anomaly", "FLOW_ANOMALY", "Anomalous flow profile (Isolation Forest)",
                                         0.3 + 0.4 * min(1.0, (anomaly_pct - 0.99) / 0.01 + 0.2),
                                         f"more unusual than {anomaly_pct * 100:.1f}% of benign flows"))

        risk = 100 * (1 - float(np.prod([1 - f["severity"] for f in findings]))) if findings else 0.0
        kinds = {f["kind"] for f in findings}
        confidence = 0.9 if kinds & {"signature", "intel"} else (0.75 if "pattern" in kinds else (0.5 if findings else 0.7))
        reasons = [Reason(code=f["id"], message=f"{f['title']} — {f['detail']}", weight=f["severity"])
                   for f in sorted(findings, key=lambda f: -f["severity"])][:6]
        ms = (time.perf_counter() - t) * 1000
        telemetry.observe_inference(self.name, ms)
        return DetectorResult(
            detector=self.name, domain=self.domain, risk_score=round(risk, 2), confidence=confidence, reason_codes=reasons,
            model_version=self.model_version, latency_ms=ms,
            metadata={"findings": findings, "src_reputation": rep_src, "dst_reputation": rep_dst, "flow_anomaly_percentile": anomaly_pct,
                      "observation": obs.to_dict()},
        )


network_detector = NetworkDetector()
