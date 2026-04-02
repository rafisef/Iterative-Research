"""SQLAlchemy ORM models mirroring the filesystem run artifacts."""
from __future__ import annotations

from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


class Run(Base):
    __tablename__ = "runs"

    id = Column(String, primary_key=True)
    started_at = Column(String, nullable=True)
    model = Column(String, nullable=True)
    temperature = Column(Float, nullable=True)
    max_tokens = Column(Integer, nullable=True)
    iterations = Column(Integer, nullable=True)
    agents = Column(Text, nullable=True)          # JSON list
    vulnerabilities = Column(Text, nullable=True)  # JSON list
    random_seed = Column(Integer, nullable=True)
    status = Column(String, default="complete")    # pending|generating|scanning|analyzing|complete|failed|cancelled
    snippet = Column(String, nullable=True)
    base_code_dir = Column(String, nullable=True)
    config_snapshot = Column(Text, nullable=True)  # full JSON config at run time

    results = relationship("Result", back_populates="run", cascade="all, delete-orphan")
    generated_codes = relationship("GeneratedCode", back_populates="run", cascade="all, delete-orphan")


class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    agent = Column(String, nullable=False)
    vulnerability_id = Column(String, nullable=False)
    iteration = Column(Integer, nullable=False)
    prompt = Column(Text, nullable=True)
    model = Column(String, nullable=True)
    success = Column(Boolean, default=True)
    server_started = Column(Boolean, default=False)
    nuclei_exit_code = Column(Integer, nullable=True)
    snippet_path = Column(String, nullable=True)
    log_path = Column(String, nullable=True)
    bandit_high = Column(Integer, default=0)
    bandit_medium = Column(Integer, default=0)
    bandit_low = Column(Integer, default=0)
    semgrep_findings = Column(Integer, default=0)
    semgrep_error = Column(Integer, default=0)
    semgrep_warning = Column(Integer, default=0)
    semgrep_info = Column(Integer, default=0)
    static_log_path = Column(String, nullable=True)
    bandit_issues = Column(Text, nullable=True)   # JSON list
    semgrep_issues = Column(Text, nullable=True)  # JSON list

    run = relationship("Run", back_populates="results")


class GeneratedCode(Base):
    __tablename__ = "generated_code"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    agent = Column(String, nullable=False)
    vuln_id = Column(String, nullable=False)
    iteration = Column(Integer, nullable=False)
    language = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    code_content = Column(Text, nullable=True)
    has_syntax_error = Column(Boolean, default=False)

    run = relationship("Run", back_populates="generated_codes")
