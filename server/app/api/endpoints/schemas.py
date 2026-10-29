from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


# System & Health Schemas
class StorageStatus(BaseModel):
    evidence_dir: str
    evidence_path: str
    reports_dir: str
    reports_path: str


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    database: str
    timestamp: datetime
    storage: StorageStatus


class SystemStatsResponse(BaseModel):
    evidence_count: int
    findings_count: int
    events_count: int
    custody_records_count: int
    benchmark_runs_count: int
    database_file: str
    collector_status: str


# Evidence Schemas
class EvidenceBase(BaseModel):
    evidence_id: str
    file_name: str
    evidence_type: str
    source_device: str
    collector_id: Optional[str] = None
    description: Optional[str] = None


class EvidenceCreate(EvidenceBase):
    pass


class EvidenceRead(EvidenceBase):
    id: int
    file_path: str
    file_size_bytes: int
    sha256_hash: str
    status: str
    is_encrypted: bool = False
    encrypted_aes_key: Optional[str] = None
    rsa_signature: Optional[str] = None
    signer_key_id: Optional[str] = None
    encryption_algorithm: Optional[str] = "AES-256-GCM"
    collected_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PublicKeyResponse(BaseModel):
    server_public_key: str
    key_algorithm: str = "RSA-OAEP"
    hash_algorithm: str = "SHA-256"
    trusted_signer_id: str
    demo_client_private_key: Optional[str] = None


class EvidenceIntegrityResult(BaseModel):
    evidence_id: str
    is_intact: bool
    stored_hash: str
    current_hash: Optional[str] = None  # None when file is missing
    status: str  # "INTACT", "TAMPERED", "FILE_MISSING"
    message: str


# Chain of Custody Schema Placeholders
class ChainOfCustodyBase(BaseModel):
    evidence_id: str
    action: str
    actor: str
    location: Optional[str] = None
    notes: Optional[str] = None


class ChainOfCustodyCreate(ChainOfCustodyBase):
    pass


class ChainOfCustodyRead(ChainOfCustodyBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


# Cryptography Lab Schemas
class CryptoLabMetadata(BaseModel):
    evidence_id: str
    file_name: str
    evidence_type: str
    file_size_bytes: int
    sha256_hash: str
    is_encrypted: bool
    encryption_algorithm: Optional[str] = "AES-256-GCM"
    signer_key_id: Optional[str] = None
    has_rsa_signature: bool = False
    has_wrapped_key: bool = False
    wrapped_key_preview: Optional[str] = None
    recorded_encryption_duration_ms: Optional[float] = None
    recorded_encryption_throughput_mbps: Optional[float] = None
    is_pcap: bool = False


class CryptoLabExecutionResult(BaseModel):
    evidence_id: str
    file_name: str
    evidence_type: str
    is_encrypted: bool
    encryption_algorithm: Optional[str] = "AES-256-GCM"
    signer_key_id: Optional[str] = None
    has_rsa_signature: bool = False
    rsa_signature_valid: bool = False
    gcm_authentication_valid: bool = False
    integrity_status: str  # "VERIFIED_INTACT", "TAMPERED", "NOT_APPLICABLE"
    original_size_bytes: int
    encrypted_size_bytes: int
    nonce_hex: Optional[str] = None
    tag_hex: Optional[str] = None
    wrapped_key_hex: Optional[str] = None
    ciphertext_preview_hex: Optional[str] = None
    ciphertext_preview_b64: Optional[str] = None
    ciphertext_preview_bytes: int = 0
    total_ciphertext_bytes: int = 0
    plaintext_preview: Optional[str] = None
    plaintext_preview_type: Optional[str] = None  # "text", "image", "binary_omitted", "unsupported"
    encryption_duration_ms: Optional[float] = None
    encryption_throughput_mbps: Optional[float] = None
    decryption_duration_ms: float
    decryption_throughput_mbps: Optional[float] = None
    is_pcap: bool = False
    message: str


# SHA-256 Hashing Demonstration Schemas
class HashMeasurement(BaseModel):
    representation_label: str
    sha256_digest: str
    file_size_bytes: int
    duration_ms: float
    throughput_mbps: float
    chunks_processed: int
    is_empty_file: bool


class EvidenceHashDemoResponse(BaseModel):
    evidence_id: str
    file_name: str
    evidence_type: str
    is_encrypted: bool
    stored_acquisition_hash: str
    hashes: List[HashMeasurement]
    note: str


class StandaloneHashResponse(BaseModel):
    file_name: str
    file_type: str
    file_size_bytes: int
    sha256_digest: str
    duration_ms: float
    throughput_mbps: float
    chunks_processed: int
    is_empty_file: bool


class HashCompareResult(BaseModel):
    input_a_label: str
    input_a_size_bytes: int
    input_a_digest: str
    input_b_label: str
    input_b_size_bytes: int
    input_b_digest: str
    digests_match: bool
    hex_character_differences: int
    bit_differences: int
    avalanche_percentage: float
    educational_note: str


# Finding Schema Placeholders
class FindingBase(BaseModel):
    finding_id: str
    evidence_id: str
    category: str
    severity: str
    title: str
    details: Optional[str] = None


class FindingRead(FindingBase):
    id: int
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AnalysisTriggerResponse(BaseModel):
    evidence_id: str
    evidence_status: str
    is_valid_pcap: bool
    packet_count: int
    total_bytes: int
    protocols: dict
    source_ips: dict
    destination_ips: dict
    source_ports: dict
    destination_ports: dict
    conversations: list
    findings_count: int
    findings: List[FindingBase]


# Investigation Event Schema Placeholders
class InvestigationEventBase(BaseModel):
    event_id: str
    evidence_id: Optional[str] = None
    event_type: str
    source: str
    severity: str = "INFO"
    message: str
    metadata_json: Optional[str] = None


class InvestigationEventRead(InvestigationEventBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


# Benchmark Result Schema Placeholders
class BenchmarkResultBase(BaseModel):
    benchmark_name: str
    evidence_id: Optional[str] = None
    sample_size_bytes: int
    duration_ms: float
    throughput_mbps: Optional[float] = None
    system_info: Optional[str] = None


class BenchmarkResultRead(BenchmarkResultBase):
    id: int
    recorded_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Forensic Report Schemas
class ReportGenerateRequest(BaseModel):
    evidence_id: str
    title: Optional[str] = None
    examiner_name: Optional[str] = "ForenSight Forensic Examiner"
    notes: Optional[str] = None
    report_scope: Optional[str] = "EVIDENCE"


class InvestigationReportRead(BaseModel):
    id: int
    report_id: str
    title: str
    report_scope: str
    evidence_id: Optional[str] = None
    generated_at: datetime
    generated_by: str
    file_size_bytes: int
    file_path: str
    notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class InvestigationReportDetail(InvestigationReportRead):
    download_url: str
    summary_data: Optional[dict] = None

