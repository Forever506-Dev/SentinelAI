"""
SentinelAI Enrollment Service

FastAPI microservice handling agent enrollment (certificate issuance),
certificate renewal, and revocation.

Deployment: Internal-only (not exposed to internet).
Dependencies: PostgreSQL (enrollment records), NATS (revocation broadcast).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# ─── Configuration ───────────────────────────────────────────────────────────

ENROLLMENT_TOKEN_TTL = timedelta(minutes=5)
CERTIFICATE_VALIDITY = timedelta(days=30)
CERTIFICATE_RENEWAL_WINDOW = timedelta(days=7)
TOKEN_HMAC_KEY = secrets.token_bytes(32)  # In production: from Vault / env


# ─── Models ──────────────────────────────────────────────────────────────────


class EnrollmentStatus(str, Enum):
    PENDING = "pending"
    ENROLLED = "enrolled"
    REVOKED = "revoked"
    EXPIRED = "expired"


class EnrollmentTokenRequest(BaseModel):
    """Admin request to generate an enrollment token."""
    tenant_id: str
    hostname_hint: str = ""
    hardware_fingerprint: str = Field(
        ...,
        description="SHA-256(SMBIOS_UUID || sorted_MAC_addresses || disk_serial)",
    )
    role: str = "endpoint"
    labels: dict[str, str] = {}


class EnrollmentTokenResponse(BaseModel):
    """Token returned to admin for delivery to endpoint."""
    token: str
    expires_at: datetime
    agent_guid: str


class EnrollmentRequest(BaseModel):
    """Agent sends this to complete enrollment."""
    token: str
    csr_pem: str  # PEM-encoded PKCS#10 CSR
    hardware_fingerprint: str
    os_type: str
    os_version: str
    agent_version: str
    hostname: str


class EnrollmentResponse(BaseModel):
    """Returned to agent on successful enrollment."""
    agent_guid: str
    signed_certificate_pem: str
    ca_chain_pem: str
    initial_policy: dict
    certificate_not_after: datetime
    renew_before: datetime


class CertRenewalRequest(BaseModel):
    """Agent requests certificate renewal before expiry."""
    agent_guid: str
    csr_pem: str
    current_cert_serial: str


class CertRenewalResponse(BaseModel):
    """New certificate issued on renewal."""
    signed_certificate_pem: str
    certificate_not_after: datetime
    renew_before: datetime


class RevocationRequest(BaseModel):
    """Admin revokes an agent certificate."""
    agent_guid: str
    reason: str


# ─── In-Memory Store (replace with PostgreSQL in production) ─────────────────

# token_hash → token record
_token_store: dict[str, dict] = {}
# agent_guid → enrollment record
_enrollment_store: dict[str, dict] = {}
# revoked certificate serials
_revoked_serials: set[str] = set()


# ─── Token Management ───────────────────────────────────────────────────────


def _hash_token(token: str) -> str:
    """Argon2id in production; SHA-256 here for simplicity."""
    return hashlib.sha256(token.encode()).hexdigest()


def _generate_token(agent_guid: str, hw_fingerprint: str) -> tuple[str, datetime]:
    """Generate a one-time enrollment token."""
    raw = secrets.token_urlsafe(48)
    # HMAC to make token tamper-evident
    mac = hmac.new(TOKEN_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()[:16]
    token = f"{raw}.{mac}"
    expires_at = datetime.now(timezone.utc) + ENROLLMENT_TOKEN_TTL

    _token_store[_hash_token(token)] = {
        "agent_guid": agent_guid,
        "hw_fingerprint": hw_fingerprint,
        "expires_at": expires_at,
        "consumed": False,
    }

    return token, expires_at


def _validate_token(token: str, hw_fingerprint: str) -> dict:
    """Validate enrollment token. Raises HTTPException on failure."""
    # Verify HMAC
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token format")

    raw, mac = parts
    expected_mac = hmac.new(TOKEN_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(mac, expected_mac):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token integrity check failed")

    # Lookup
    token_hash = _hash_token(token)
    record = _token_store.get(token_hash)
    if not record:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown token")

    if record["consumed"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "token already consumed")

    if datetime.now(timezone.utc) > record["expires_at"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token expired")

    if record["hw_fingerprint"] != hw_fingerprint:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "hardware fingerprint mismatch — token bound to different machine",
        )

    # Mark consumed (atomic in production via DB transaction)
    record["consumed"] = True

    return record


# ─── Certificate Authority (Stub) ───────────────────────────────────────────


class TenantCA:
    """
    In production, this wraps a per-tenant intermediate CA.

    CA hierarchy:
      Root CA (offline, HSM) → Tenant Sub-CA (per tenant) → Agent Certs

    For this stub, we generate a self-signed CA on startup.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        # Generate ephemeral CA key (in production: loaded from secure storage)
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        self._ca_cert = self._generate_ca_cert()

    def _generate_ca_cert(self) -> x509.Certificate:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"SentinelAI Tenant CA - {self.tenant_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SentinelAI"),
        ])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

    def sign_csr(
        self,
        csr_pem: str,
        agent_guid: str,
        validity: timedelta = CERTIFICATE_VALIDITY,
    ) -> x509.Certificate:
        """Sign an agent's CSR with this tenant's CA."""
        csr = x509.load_pem_x509_csr(csr_pem.encode())

        # Validate CSR
        if not csr.is_signature_valid:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid CSR signature")

        # Build certificate
        # CN format: agent:<agent_guid>@tenant:<tenant_id>
        subject = x509.Name([
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                f"agent:{agent_guid}@tenant:{self.tenant_id}",
            ),
        ])

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + validity)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        return cert

    @property
    def ca_chain_pem(self) -> str:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()


# ─── Tenant CA Registry ─────────────────────────────────────────────────────

# In production: loaded from Vault / HSM per tenant
_tenant_cas: dict[str, TenantCA] = {}


def _get_tenant_ca(tenant_id: str) -> TenantCA:
    if tenant_id not in _tenant_cas:
        _tenant_cas[tenant_id] = TenantCA(tenant_id)
    return _tenant_cas[tenant_id]


# ─── Default Policy ─────────────────────────────────────────────────────────

DEFAULT_AGENT_POLICY = {
    "collection": {
        "process": {"enabled": True, "include_command_line": True},
        "file": {"enabled": True, "sensitive_paths": [
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "/etc/",
            "/usr/bin/",
        ]},
        "network": {"enabled": True, "capture_dns": True},
        "registry": {"enabled": True, "persistence_keys_only": False},
        "module_load": {"enabled": True, "signed_only_alert": True},
    },
    "transport": {
        "batch_max_events": 256,
        "batch_max_delay_ms": 5000,
        "compression": "zstd",
    },
    "local_detection": {
        "enabled": True,
        "sigma_rules_version": "2024.01.15",
    },
    "heartbeat_interval_seconds": 60,
}


# ─── FastAPI Application ────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelAI Enrollment Service",
    version="2.0.0",
    docs_url="/docs",
)


@app.post(
    "/api/v2/enrollment/token",
    response_model=EnrollmentTokenResponse,
    summary="Generate enrollment token (admin)",
)
async def generate_enrollment_token(req: EnrollmentTokenRequest):
    """
    Admin-only endpoint to generate a one-time enrollment token.
    Token is bound to hardware fingerprint and expires in 5 minutes.
    """
    agent_guid = str(uuid.uuid4())
    token, expires_at = _generate_token(agent_guid, req.hardware_fingerprint)

    # Pre-create enrollment record
    _enrollment_store[agent_guid] = {
        "tenant_id": req.tenant_id,
        "hostname_hint": req.hostname_hint,
        "labels": req.labels,
        "role": req.role,
        "status": EnrollmentStatus.PENDING,
        "created_at": datetime.now(timezone.utc),
    }

    return EnrollmentTokenResponse(
        token=token,
        expires_at=expires_at,
        agent_guid=agent_guid,
    )


@app.post(
    "/api/v2/enrollment/enroll",
    response_model=EnrollmentResponse,
    summary="Complete agent enrollment",
)
async def enroll_agent(req: EnrollmentRequest):
    """
    Agent calls this with the enrollment token + CSR to receive
    a signed mTLS certificate and initial collection policy.
    """
    # 1. Validate token
    token_record = _validate_token(req.token, req.hardware_fingerprint)
    agent_guid = token_record["agent_guid"]

    # 2. Get enrollment record
    enrollment = _enrollment_store.get(agent_guid)
    if not enrollment:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "enrollment record not found")

    # 3. Sign CSR with tenant CA
    tenant_id = enrollment["tenant_id"]
    ca = _get_tenant_ca(tenant_id)
    signed_cert = ca.sign_csr(req.csr_pem, agent_guid)

    # 4. Update enrollment record
    enrollment["status"] = EnrollmentStatus.ENROLLED
    enrollment["enrolled_at"] = datetime.now(timezone.utc)
    enrollment["hostname"] = req.hostname
    enrollment["os_type"] = req.os_type
    enrollment["os_version"] = req.os_version
    enrollment["agent_version"] = req.agent_version
    enrollment["cert_serial"] = str(signed_cert.serial_number)
    enrollment["cert_not_after"] = signed_cert.not_valid_after_utc

    renew_before = signed_cert.not_valid_after_utc - CERTIFICATE_RENEWAL_WINDOW

    return EnrollmentResponse(
        agent_guid=agent_guid,
        signed_certificate_pem=signed_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode(),
        ca_chain_pem=ca.ca_chain_pem,
        initial_policy=DEFAULT_AGENT_POLICY,
        certificate_not_after=signed_cert.not_valid_after_utc,
        renew_before=renew_before,
    )


@app.post(
    "/api/v2/enrollment/renew",
    response_model=CertRenewalResponse,
    summary="Renew agent certificate",
)
async def renew_certificate(req: CertRenewalRequest):
    """
    Agent calls this before certificate expiry to get a new cert.
    Must present current valid certificate (verified at TLS layer).
    """
    enrollment = _enrollment_store.get(req.agent_guid)
    if not enrollment:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not enrolled")

    if enrollment["status"] == EnrollmentStatus.REVOKED:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "agent certificate revoked")

    # Verify the serial matches what we issued
    if enrollment.get("cert_serial") != req.current_cert_serial:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "certificate serial mismatch")

    # Sign new CSR
    tenant_id = enrollment["tenant_id"]
    ca = _get_tenant_ca(tenant_id)
    new_cert = ca.sign_csr(req.csr_pem, req.agent_guid)

    # Update record
    enrollment["cert_serial"] = str(new_cert.serial_number)
    enrollment["cert_not_after"] = new_cert.not_valid_after_utc
    enrollment["last_renewed_at"] = datetime.now(timezone.utc)

    renew_before = new_cert.not_valid_after_utc - CERTIFICATE_RENEWAL_WINDOW

    return CertRenewalResponse(
        signed_certificate_pem=new_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode(),
        certificate_not_after=new_cert.not_valid_after_utc,
        renew_before=renew_before,
    )


@app.post(
    "/api/v2/enrollment/revoke",
    summary="Revoke agent certificate (admin)",
)
async def revoke_agent(req: RevocationRequest):
    """
    Admin revokes an agent's certificate. The revoked serial is
    broadcast via NATS to all ingestion gateways within 30 seconds.
    """
    enrollment = _enrollment_store.get(req.agent_guid)
    if not enrollment:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")

    cert_serial = enrollment.get("cert_serial", "")
    _revoked_serials.add(cert_serial)

    enrollment["status"] = EnrollmentStatus.REVOKED
    enrollment["revoked_at"] = datetime.now(timezone.utc)
    enrollment["revoke_reason"] = req.reason

    # TODO: Publish to NATS system.certs.revoked
    # nats_client.publish("system.certs.revoked", cert_serial.encode())

    return {"status": "revoked", "agent_guid": req.agent_guid, "cert_serial": cert_serial}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "enrollment"}
