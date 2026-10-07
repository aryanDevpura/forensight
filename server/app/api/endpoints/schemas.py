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
    collected_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


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


# Investigation Event Schema Placeholders
class InvestigationEventBase(BaseModel):
    event_id: str
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
    sample_size_bytes: int
    duration_ms: float
    throughput_mbps: Optional[float] = None
    system_info: Optional[str] = None


class BenchmarkResultRead(BenchmarkResultBase):
    id: int
    recorded_at: datetime

    model_config = ConfigDict(from_attributes=True)
