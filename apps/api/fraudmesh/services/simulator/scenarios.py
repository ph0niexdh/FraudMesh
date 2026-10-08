"""Attack scenarios (DEMO / SIMULATION).

Each scenario is a list of steps. A step is either an event (sent through the real
ingestion path) or a media step (real deepfake / KYC inference on the controlled
fixtures, whose stored result is then referenced by a KYC / BIOMETRIC event).

``at`` is the event-time offset in minutes from the scenario anchor; ``pause`` is
the wall-clock delay before emitting (so the UI can be watched evolving).
Attacker infrastructure is unique per run (fresh device / IP suffix) so repeated
demo runs remain independent attacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fraudmesh.services.simulator.population import DEMO_VICTIM_ID, MULE_RING_BENEFICIARY


@dataclass
class Step:
    label: str
    at: float  # minutes from anchor (event time)
    event: dict[str, Any] | None = None
    media: dict[str, Any] | None = None  # {"kind": "kyc"|"selfie", "document": fixture, "selfie": fixture, "event_type": ...}
    pause: float = 1.6
    repeat: int = 1  # emit N similar events (bursts), varied by index


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    anchor: str  # "now" | "midnight"
    steps: list[Step] = field(default_factory=list)
    expected: str = ""


def _login(ip, device, success=True, geo=None, **kw):
    return {"event_type": "LOGIN", "ip": ip, "device": device, "geo": geo, "payload": {"success": success, **kw}}


def build(scenario_id: str, run: str, victim: dict) -> Scenario:
    """``run`` = short run suffix; ``victim`` = {"customer_id", "account_id", "device_id", "ip", "device_model", "home": (lat, lon)}"""
    atk_ip = f"203.0.113.{40 + int(run[:2], 16) % 200}"
    atk_dev = {"id": f"atk-{run}", "model": "Pixel 7", "os": "Android 14", "browser": "Chrome 129", "timezone": "Europe/Bucharest"}
    vic_dev = {"id": victim["device_id"].removeprefix("dev:"), "model": victim.get("device_model", "Galaxy S23"), "os": "Android 14"}
    cust, acct = victim["customer_id"], victim["account_id"]
    home = victim.get("home", (19.076, 72.877))
    far = {"lat": 44.43, "lon": 26.10, "city": "Bucharest", "country": "RO"}

    def ev(d: dict) -> dict:
        return {"customer_id": cust, "account_id": acct, **d}

    def zeek(log_type: str, rec: dict) -> dict:
        return {"event_type": "NETWORK", "payload": {"sensor": "zeek", "log_type": log_type, "record": rec}}

    if scenario_id == "NORMAL":
        return Scenario("NORMAL", "Normal customer", "Routine session: known device, home network, everyday payments.", "now", [
            Step("Login from known device", 0, ev(_login(victim["ip"], vic_dev, geo={"lat": home[0], "lon": home[1]}, session_duration_s=240))),
            Step("Grocery payment", 2, ev({"event_type": "TRANSACTION", "ip": victim["ip"], "device": vic_dev,
                                           "payload": {"amount": 1840, "channel": "upi", "merchant_category": "grocery", "merchant_id": "m-freshmart"}})),
            Step("Electricity bill", 4, ev({"event_type": "TRANSACTION", "ip": victim["ip"], "device": vic_dev,
                                            "payload": {"amount": 2310, "channel": "upi", "merchant_category": "utilities", "merchant_id": "m-power-co"}})),
        ], "No case. Events scored LOW and allowed.")

    if scenario_id == "ACCOUNT_TAKEOVER":
        return Scenario("ACCOUNT_TAKEOVER", "Midnight account takeover + deepfake KYC",
                        "Stolen credentials, new device and network, MFA reset, deepfake re-verification, mule beneficiary, high-value transfer.",
                        "midnight", [
            Step("Legitimate evening session", -315, ev(_login(victim["ip"], vic_dev, geo={"lat": home[0], "lon": home[1]}, session_duration_s=260))),
            Step("Legitimate payment", -310, ev({"event_type": "TRANSACTION", "ip": victim["ip"], "device": vic_dev,
                                                 "payload": {"amount": 1260, "channel": "upi", "merchant_category": "dining", "merchant_id": "m-cafe"}})),
            Step("Credential-stuffing burst against login (IDS)", -6, zeek("http", {
                "ts": None, "uid": f"C{run}h", "id.orig_h": atk_ip, "id.orig_p": 41000, "id.resp_h": "10.20.0.15", "id.resp_p": 443,
                "proto": "tcp", "method": "POST", "host": "netbanking.demo-bank.example", "uri": "/api/login", "status_code": 401,
                "user_agent": "python-requests/2.31"}), pause=0.25, repeat=9),
            Step("New device + new IP login", 0, ev(_login(atk_ip, atk_dev, geo=far, session_duration_s=95, navigation_speed_ratio=3.8)), pause=2.2),
            Step("Device registered", 1, ev({"event_type": "DEVICE", "ip": atk_ip, "device": atk_dev, "payload": {"action": "registered"}})),
            Step("MFA reset", 2, ev({"event_type": "MFA", "ip": atk_ip, "device": atk_dev, "payload": {"action": "reset", "factor": "totp"}}), pause=2.0),
            Step("KYC re-verification with deepfake selfie", 4, ev({"event_type": "KYC", "ip": atk_ip, "device": atk_dev, "payload": {}}),
                 media={"kind": "kyc", "document": "id_document_genuine.png", "selfie": "deepfake_faceswap.png"}, pause=1.0),
            Step("Attacker TLS session (IDS)", 5, zeek("ssl", {
                "ts": None, "uid": f"C{run}s", "id.orig_h": atk_ip, "id.orig_p": 51544, "id.resp_h": "10.20.0.15", "id.resp_p": 443, "proto": "tcp",
                "server_name": "netbanking.demo-bank.example", "ja3": "6734f37431670b3ab4292b8f60f29984", "validation_status": "ok"})),
            Step("DNS lookup to C2 domain (IDS)", 5.5, zeek("dns", {
                "ts": None, "uid": f"C{run}d", "id.orig_h": atk_ip, "id.orig_p": 5353, "id.resp_h": "10.20.0.53", "id.resp_p": 53, "proto": "udp",
                "query": "x7kq9zv2mtr8wplq4n.cdn-sync-update.example", "rcode_name": "NOERROR"})),
            Step("New beneficiary (mule ring)", 7, ev({"event_type": "BENEFICIARY", "ip": atk_ip, "device": atk_dev,
                                                       "payload": {"action": "added", "beneficiary_id": MULE_RING_BENEFICIARY, "beneficiary_name": "R. Kumar"}})),
            Step("₹1,85,000 transfer", 10, ev({"event_type": "TRANSACTION", "ip": atk_ip, "device": atk_dev, "geo": far,
                                              "payload": {"amount": 185000, "channel": "imps", "merchant_category": "p2p_transfer",
                                                          "beneficiary_id": MULE_RING_BENEFICIARY, "beneficiary_name": "R. Kumar"}}), pause=2.5),
        ], "One CRITICAL case (≈ 9-10 correlated events), transfer BLOCKED, beneficiary linked to 2 flagged mule accounts.")

    if scenario_id == "DEEPFAKE_KYC":
        return Scenario("DEEPFAKE_KYC", "Deepfake KYC onboarding", "Synthetic identity: tampered document and face-swapped selfie, then cash-out attempt.", "now", [
            Step("Onboarding login from emulator", 0, ev(_login(atk_ip, {**atk_dev, "emulator": True}, geo=far))),
            Step("KYC: tampered document + deepfake selfie", 2, ev({"event_type": "KYC", "ip": atk_ip, "device": {**atk_dev, "emulator": True}, "payload": {}}),
                 media={"kind": "kyc", "document": "id_document_tampered.png", "selfie": "deepfake_faceswap.png"}),
            Step("Liveness video", 4, ev({"event_type": "BIOMETRIC", "ip": atk_ip, "device": {**atk_dev, "emulator": True}, "payload": {}}),
                 media={"kind": "selfie", "selfie": "deepfake_selfie.mp4"}),
            Step("Beneficiary added", 6, ev({"event_type": "BENEFICIARY", "ip": atk_ip, "device": {**atk_dev, "emulator": True},
                                            "payload": {"action": "added", "beneficiary_id": f"ben-cash-{run}", "beneficiary_name": "Cash-out wallet"}})),
            Step("Transfer attempt", 8, ev({"event_type": "TRANSACTION", "ip": atk_ip, "device": {**atk_dev, "emulator": True},
                                          "payload": {"amount": 48000, "channel": "imps", "merchant_category": "p2p_transfer", "beneficiary_id": f"ben-cash-{run}"}})),
        ], "Verification HOLD; deepfake + tampered-document evidence in one case.")

    if scenario_id == "MULE_RING":
        mules = ["cust_mule2", "cust_mule3", "cust_mule4"]
        steps = []
        for i, m in enumerate(mules):
            steps.append(Step(f"Mule {i + 1} login on shared handset", i * 3, {
                "customer_id": m, "account_id": f"acc_{m[5:]}_0", **_login(f"198.51.100.{20 + i}", {"id": "mule-ring-handset", "model": "Redmi 9A", "os": "Android 11"})}, pause=1.0))
            steps.append(Step(f"Mule {i + 1} forwards funds", i * 3 + 1, {
                "customer_id": m, "account_id": f"acc_{m[5:]}_0", "event_type": "TRANSACTION", "ip": f"198.51.100.{20 + i}",
                "device": {"id": "mule-ring-handset", "model": "Redmi 9A", "os": "Android 11"},
                "payload": {"amount": 64000 + 7000 * i, "channel": "imps", "merchant_category": "p2p_transfer", "beneficiary_id": MULE_RING_BENEFICIARY,
                            "beneficiary_name": "R. Kumar"}}, pause=1.2))
        return Scenario("MULE_RING", "Money-mule ring", "Three accounts on one shared handset forwarding funds to the same cash-out beneficiary.", "now", steps,
                        "Graph engine links the accounts via the shared device and the flagged beneficiary; transfers held.")

    if scenario_id == "CREDENTIAL_STUFFING":
        targets = ["cust_0003", "cust_0011", "cust_0019", "cust_0027", "cust_0035"]
        steps = [Step("Credential-stuffing traffic (IDS)", 0, zeek("http", {
            "ts": None, "uid": f"S{run}", "id.orig_h": atk_ip, "id.orig_p": 40100, "id.resp_h": "10.20.0.15", "id.resp_p": 443, "proto": "tcp",
            "method": "POST", "host": "netbanking.demo-bank.example", "uri": "/api/login", "status_code": 401, "user_agent": "OpenBullet/1.4"}),
            pause=0.2, repeat=12)]
        for i, t in enumerate(targets):
            steps.append(Step(f"Failed login {t}", 1 + i * 0.2, {"customer_id": t, "account_id": f"acc_{t[5:]}_0",
                                                                **_login(atk_ip, atk_dev, success=False, failure_reason="bad_password")}, pause=0.4, repeat=2))
        steps.append(Step("Successful login (hit)", 3, {"customer_id": targets[2], "account_id": f"acc_{targets[2][5:]}_0", **_login(atk_ip, atk_dev, geo=far)}))
        steps.append(Step("MFA factor changed", 4, {"customer_id": targets[2], "account_id": f"acc_{targets[2][5:]}_0", "event_type": "MFA", "ip": atk_ip,
                                                   "device": atk_dev, "payload": {"action": "factor_changed", "factor": "sms", "channel_changed_to": "new SIM"}}))
        return Scenario("CREDENTIAL_STUFFING", "Credential stuffing", "Botnet replays leaked credentials; one account is breached.", "now", steps,
                        "IDS stuffing alerts + failed logins + breached account correlate via attacker IP.")

    if scenario_id == "CLOUD_COMPROMISE":
        principal = f"svc-payments-ci-{run[:4]}"
        tor = "192.0.2.66"

        def cloud(action, resource, mfa=False):
            return {"event_type": "CLOUD", "ip": tor, "payload": {"provider": "aws", "principal": principal, "action": action, "resource": resource,
                                                                  "region": "ap-south-1", "mfa_used": mfa}}
        return Scenario("CLOUD_COMPROMISE", "Cloud identity compromise", "Leaked CI key used from TOR: privilege escalation, logging disabled, data access.", "now", [
            Step("Suricata: TOR exit to cloud API", 0, {"event_type": "IDS", "payload": {"sensor": "suricata", "record": {
                "timestamp": None, "event_type": "alert", "src_ip": tor, "src_port": 50211, "dest_ip": "10.30.0.10", "dest_port": 443, "proto": "TCP",
                "alert": {"signature": "ET POLICY TOR exit node traffic to cloud management API", "signature_id": 2034001, "severity": 2, "category": "Potentially Bad Traffic"}}}}),
            Step("CreateAccessKey", 1, cloud("iam:CreateAccessKey", f"arn:aws:iam::123456789012:user/{principal}")),
            Step("AttachUserPolicy (admin)", 2, cloud("iam:AttachUserPolicy", "arn:aws:iam::aws:policy/AdministratorAccess")),
            Step("StopLogging", 3, cloud("cloudtrail:StopLogging", "arn:aws:cloudtrail:ap-south-1:123456789012:trail/org-trail")),
            Step("Read secrets", 4, cloud("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:ap-south-1:123456789012:secret:core-banking-db")),
        ], "One cloud-compromise case correlated through the TOR IP.")

    if scenario_id == "INSIDER":
        insider_ip = "10.44.8.23"
        principal = "ops.analyst.k"
        tgt = "cust_0042"
        return Scenario("INSIDER", "Insider-assisted takeover", "Employee identity bulk-reads customer data at night, then a customer's MFA is reset from the same workstation.", "now", [
            Step("Bulk customer-data read", 0, {"event_type": "CLOUD", "ip": insider_ip, "payload": {"provider": "aws", "principal": principal,
                    "action": "s3:GetObject", "resource": "arn:aws:s3:::kyc-archive/customers/export-2026.csv", "mfa_used": True}}),
            Step("Secrets access", 1, {"event_type": "CLOUD", "ip": insider_ip, "payload": {"provider": "aws", "principal": principal,
                    "action": "secretsmanager:GetSecretValue", "resource": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:otp-gateway", "mfa_used": True}}),
            Step("Customer MFA reset from insider workstation", 6, {"customer_id": tgt, "account_id": f"acc_{tgt[5:]}_0", "event_type": "MFA", "ip": insider_ip,
                    "device": {"id": f"ws-{run}", "model": "Workstation", "os": "Windows 11"}, "payload": {"action": "reset", "factor": "sms"}}),
            Step("Login with new factor", 8, {"customer_id": tgt, "account_id": f"acc_{tgt[5:]}_0", **_login(insider_ip, {"id": f"ws-{run}", "model": "Workstation", "os": "Windows 11"})}),
            Step("Beneficiary added", 9, {"customer_id": tgt, "account_id": f"acc_{tgt[5:]}_0", "event_type": "BENEFICIARY", "ip": insider_ip,
                    "device": {"id": f"ws-{run}", "model": "Workstation", "os": "Windows 11"}, "payload": {"action": "added", "beneficiary_id": f"ben-ins-{run}"}}),
            Step("Transfer", 11, {"customer_id": tgt, "account_id": f"acc_{tgt[5:]}_0", "event_type": "TRANSACTION", "ip": insider_ip,
                    "device": {"id": f"ws-{run}", "model": "Workstation", "os": "Windows 11"},
                    "payload": {"amount": 92000, "channel": "neft", "merchant_category": "p2p_transfer", "beneficiary_id": f"ben-ins-{run}"}}),
        ], "Cloud + customer events correlate through the insider workstation IP.")

    raise KeyError(scenario_id)


CATALOG = [
    {"id": "NORMAL", "name": "Normal user", "severity": "LOW"},
    {"id": "ACCOUNT_TAKEOVER", "name": "Account takeover + deepfake KYC", "severity": "CRITICAL", "flagship": True},
    {"id": "MULE_RING", "name": "Mule ring", "severity": "HIGH"},
    {"id": "DEEPFAKE_KYC", "name": "Deepfake KYC onboarding", "severity": "CRITICAL"},
    {"id": "CREDENTIAL_STUFFING", "name": "Credential stuffing", "severity": "HIGH"},
    {"id": "INSIDER", "name": "Insider-assisted takeover", "severity": "HIGH"},
    {"id": "CLOUD_COMPROMISE", "name": "Cloud compromise", "severity": "HIGH"},
]
