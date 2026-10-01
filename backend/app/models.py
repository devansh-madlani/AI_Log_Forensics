"""
ORM models.

Design note (forensic principle - preserve evidence):
`raw_data` is written once at ingestion time and is never updated by any
later pipeline stage. ML/risk fields (anomaly_score, risk_score,
risk_level, analysis_reasons) are the only columns a re-run of analysis
is allowed to touch.
"""

from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime
from sqlalchemy.sql import func

from app.database import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_uid = Column(String, unique=True, index=True, nullable=False)

    # Evidence-integrity tag - see schemas.DataOrigin
    data_origin = Column(String, nullable=False, default="OBSERVED", index=True)
    # Canonical OS/source scope for isolated analysis and investigation views.
    # Nullable for any legacy or future source that cannot establish an OS.
    operating_system = Column(String, nullable=True, index=True)

    # Core normalized fields
    timestamp = Column(String, index=True, nullable=False)  # ISO-8601 string
    event_id = Column(Integer, index=True, nullable=True)
    log_source = Column(String, index=True, nullable=False)
    provider = Column(String, nullable=True)
    level = Column(String, nullable=True)
    computer = Column(String, nullable=True)
    user = Column(String, nullable=True, index=True)
    process_id = Column(Integer, nullable=True)
    message = Column(Text, nullable=True)

    # Extended fields
    parent_process = Column(String, nullable=True)
    process_name = Column(String, nullable=True, index=True)
    command_line = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)

    # Descriptive
    event_type = Column(String, index=True, nullable=False, default="Unknown")
    severity = Column(String, nullable=True)

    # Evidence preservation - never overwritten after insert
    raw_data = Column(Text, nullable=False, default="")

    # Feature extraction output (JSON-encoded dict), useful for
    # investigator transparency / debugging the ML stage
    features_json = Column(Text, nullable=True)

    # --- ML anomaly detection output ------------------------------------
    # Raw, unsupervised anomaly signal from Isolation Forest, normalized
    # to 0-1 (1 = most anomalous). This is a STATISTICAL signal only.
    anomaly_score = Column(Float, nullable=True)

    # --- Forensic risk score ---------------------------------------------
    # 0-100 investigator-facing score that combines the ML anomaly_score
    # with simple, explainable contextual rules. Deliberately a different
    # number from anomaly_score - see scoring/risk_scoring.py
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True, index=True)  # LOW/MEDIUM/HIGH/CRITICAL

    # JSON-encoded list of human-readable reason strings
    analysis_reasons = Column(Text, nullable=True)

    analyzed = Column(Boolean, default=False, index=True)
    batch_id = Column(String, index=True, nullable=True)

    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    analyzed_at = Column(DateTime(timezone=True), nullable=True)
