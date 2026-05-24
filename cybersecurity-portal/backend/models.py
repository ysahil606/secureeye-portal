from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean,
    DateTime, ForeignKey, Enum, JSON
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import enum


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class AdvisoryStatus(str, enum.Enum):
    pending = "pending"
    published = "published"
    archived = "archived"
    rejected = "rejected"


class AdvisorySource(str, enum.Enum):
    manual = "manual"
    external = "external"


class SeverityLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.viewer)
    is_active = Column(Boolean, default=True)
    alert_subscribed = Column(Boolean, default=True)
    alert_critical_only = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))

    advisories = relationship("Advisory", back_populates="author")
    annotations = relationship("AdvisoryAnnotation", back_populates="user")


class Sector(Base):
    __tablename__ = "sectors"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    risk_score = Column(Float, default=0.0)

    advisories = relationship("Advisory", back_populates="sector")


class APTGroup(Base):
    __tablename__ = "apt_groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    aliases = Column(JSON, default=[])
    description = Column(Text)
    origin_country = Column(String)
    first_seen = Column(DateTime(timezone=True))
    target_sectors = Column(JSON, default=[])
    target_countries = Column(JSON, default=[])
    common_ttps = Column(JSON, default=[])
    is_active = Column(Boolean, default=True)


class WarRoomMessage(Base):
    __tablename__ = "war_room_messages"
    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")


class WarRoomEvidence(Base):
    __tablename__ = "war_room_evidence"
    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    file_name = Column(String)
    file_path = Column(String)
    file_type = Column(String)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")



class Advisory(Base):
    __tablename__ = "advisories"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False, index=True)
    description = Column(Text)
    mitigation = Column(Text)
    ai_summary = Column(Text)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.medium)
    cvss_score = Column(Float)
    status = Column(Enum(AdvisoryStatus), default=AdvisoryStatus.pending)
    source = Column(Enum(AdvisorySource), default=AdvisorySource.manual)
    sector_id = Column(Integer, ForeignKey("sectors.id"))
    author_id = Column(Integer, ForeignKey("users.id"))
    cve_ids = Column(JSON, default=[])           # list of CVE IDs
    iocs = Column(JSON, default=[])              # list of IOC dicts
    affected_vendors = Column(JSON, default=[])  # list of vendor names
    attack_types = Column(JSON, default=[])      # RCE, SQLi, XSS, etc.
    apt_groups = Column(JSON, default=[])        # APT group names
    mitre_ttps = Column(JSON, default=[])        # MITRE ATT&CK TTP IDs
    is_zero_day = Column(Boolean, default=False)
    zero_day_status = Column(String)             # Exploited / Patch Available / Mitigated
    is_kev = Column(Boolean, default=False)      # CISA Known Exploited Vulnerability
    is_critical_alert = Column(Boolean, default=False)
    source_url = Column(String)
    external_id = Column(String, unique=True)    # deduplication key
    published_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    sector = relationship("Sector", back_populates="advisories")
    author = relationship("User", back_populates="advisories")
    annotations = relationship("AdvisoryAnnotation", back_populates="advisory")
    tasks = relationship("AnalystTask", back_populates="advisory")


class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, nullable=False, index=True)
    ioc_type = Column(String, nullable=False)  # ip, domain, hash, url
    source = Column(String)
    advisory_ids = Column(JSON, default=[])
    threat_score = Column(Float)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    tags = Column(JSON, default=[])

    # Enrichment fields
    country = Column(String)
    country_code = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    enrichment_data = Column(JSON, default={})



class AlertLog(Base):
    __tablename__ = "alert_logs"
    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id"))
    channel = Column(String)   # email, slack, teams
    recipients = Column(JSON)
    status = Column(String)    # sent, failed
    error_msg = Column(Text)
    sent_at = Column(DateTime(timezone=True), server_default=func.now())


class AdvisoryAnnotation(Base):
    __tablename__ = "advisory_annotations"
    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    advisory = relationship("Advisory", back_populates="annotations")
    user = relationship("User", back_populates="annotations")


class AnalystTask(Base):
    __tablename__ = "analyst_tasks"
    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id"))
    assigned_to = Column(Integer, ForeignKey("users.id"))
    assigned_by = Column(Integer, ForeignKey("users.id"))
    title = Column(String, nullable=False)
    status = Column(String, default="open")  # open, in_review, resolved
    due_date = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    advisory = relationship("Advisory", back_populates="tasks")


class FeedLog(Base):
    __tablename__ = "feed_logs"
    id = Column(Integer, primary_key=True, index=True)
    feed_source = Column(String)
    items_fetched = Column(Integer, default=0)
    items_new = Column(Integer, default=0)
    items_duplicate = Column(Integer, default=0)
    status = Column(String)
    error_msg = Column(Text)
    run_at = Column(DateTime(timezone=True), server_default=func.now())


class RolePermission(Base):
    __tablename__ = "role_permissions"
    id = Column(Integer, primary_key=True, index=True)
    role = Column(String, index=True)  # 'analyst', 'viewer'
    feature = Column(String, index=True) # 'dashboard', 'advisories', 'search', etc.
    is_allowed = Column(Boolean, default=True)


class MediaItem(Base):
    __tablename__ = "media_items"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    url = Column(String, unique=True, index=True, nullable=False)
    thumbnail_url = Column(String)
    source_name = Column(String, index=True)
    media_type = Column(String, index=True)  # 'video', 'podcast', 'article'
    published_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
