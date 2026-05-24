from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List, Any
from datetime import datetime
from models import UserRole, AdvisoryStatus, AdvisorySource, SeverityLevel


# ── Auth ──────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserOut"


class RefreshRequest(BaseModel):
    refresh_token: str


# ── User ──────────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    password: str
    role: UserRole = UserRole.viewer


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    alert_subscribed: Optional[bool] = None
    alert_critical_only: Optional[bool] = None


class UserOut(BaseModel):
    id: int
    email: str
    username: str
    full_name: str
    role: UserRole
    is_active: bool
    alert_subscribed: bool
    alert_critical_only: bool
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Sector ────────────────────────────────────────────────────────────────────
class SectorCreate(BaseModel):
    name: str
    description: Optional[str] = None


class SectorOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ── Advisory ─────────────────────────────────────────────────────────────────
class AdvisoryCreate(BaseModel):
    title: str
    description: str
    mitigation: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.medium
    cvss_score: Optional[float] = None
    sector_id: Optional[int] = None
    cve_ids: List[str] = []
    iocs: List[dict] = []
    affected_vendors: List[str] = []
    attack_types: List[str] = []
    apt_groups: List[str] = []
    mitre_ttps: List[str] = []
    is_zero_day: bool = False
    zero_day_status: Optional[str] = None
    source_url: Optional[str] = None


class AdvisoryUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    mitigation: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    cvss_score: Optional[float] = None
    sector_id: Optional[int] = None
    status: Optional[AdvisoryStatus] = None
    cve_ids: Optional[List[str]] = None
    iocs: Optional[List[dict]] = None
    affected_vendors: Optional[List[str]] = None
    attack_types: Optional[List[str]] = None
    apt_groups: Optional[List[str]] = None
    mitre_ttps: Optional[List[str]] = None
    is_zero_day: Optional[bool] = None
    zero_day_status: Optional[str] = None


class AdvisoryOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    mitigation: Optional[str]
    ai_summary: Optional[str]
    severity: SeverityLevel
    cvss_score: Optional[float]
    status: AdvisoryStatus
    source: AdvisorySource
    sector_id: Optional[int]
    sector: Optional[SectorOut]
    author_id: Optional[int]
    author: Optional[UserOut]
    cve_ids: Optional[List[Any]] = []
    iocs: Optional[List[Any]] = []
    affected_vendors: Optional[List[Any]] = []
    attack_types: Optional[List[Any]] = []
    apt_groups: Optional[List[Any]] = []
    mitre_ttps: Optional[List[Any]] = []
    is_zero_day: bool
    zero_day_status: Optional[str]
    is_kev: bool
    is_critical_alert: bool
    source_url: Optional[str]
    published_at: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class AdvisoryListOut(BaseModel):
    items: List[AdvisoryOut]
    total: int
    page: int
    per_page: int
    total_pages: int


class ExternalSearchResultOut(BaseModel):
    title: str
    description: Optional[str] = None
    source_name: str
    source_type: str
    source_url: Optional[str] = None
    display_url: Optional[str] = None
    published_at: Optional[datetime] = None
    severity: Optional[SeverityLevel] = None
    cvss_score: Optional[float] = None
    cve_ids: List[str] = []
    affected_vendors: List[str] = []
    tags: List[str] = []
    is_kev: bool = False


class SmartSearchOut(BaseModel):
    query: str
    local_items: List[AdvisoryOut]
    external_items: List[ExternalSearchResultOut]
    external_provider: str
    search_mode: str
    configuration_hint: Optional[str] = None
    local_total: int
    external_total: int
    total: int


# ── IOC ───────────────────────────────────────────────────────────────────────
class IOCCreate(BaseModel):
    value: str
    ioc_type: str  # ip, domain, hash, url
    source: Optional[str] = None
    tags: List[str] = []


class IOCOut(BaseModel):
    id: int
    value: str
    ioc_type: str
    source: Optional[str]
    advisory_ids: Optional[List[Any]] = []
    threat_score: Optional[float]
    first_seen: datetime
    last_seen: Optional[datetime]
    is_active: bool
    tags: Optional[List[Any]] = []
    
    # New enrichment fields
    country: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    enrichment_data: Optional[dict] = {}

    class Config:
        from_attributes = True


class IOCExternalResultOut(BaseModel):
    value: str
    ioc_type: str
    source_name: str
    source_url: Optional[str] = None
    display_url: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []


class IOCSearchOut(BaseModel):
    query: str
    local_items: List[IOCOut]
    external_items: List[IOCExternalResultOut]
    local_total: int
    external_total: int
    total: int
    search_mode: str
    configuration_hint: Optional[str] = None


# ── Dashboard ─────────────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_advisories: int
    manual_count: int
    external_count: int
    critical_today: int
    active_sectors: int
    zero_days_tracked: int
    pending_review: int
    published_this_week: int
    kev_count: int
    sector_distribution: List[dict]
    trending_cves: List[dict]
    severity_breakdown: dict
    recent_advisories: List[AdvisoryOut]
    secure_advisories: List[AdvisoryOut]
    open_source_advisories: List[AdvisoryOut]
    feed_last_run: Optional[datetime]


# ── Annotation ────────────────────────────────────────────────────────────────
class AnnotationCreate(BaseModel):
    content: str


class AnnotationOut(BaseModel):
    id: int
    advisory_id: int
    user_id: int
    user: Optional[UserOut]
    content: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Task ──────────────────────────────────────────────────────────────────────
class TaskCreate(BaseModel):
    advisory_id: int
    assigned_to: int
    title: str
    due_date: Optional[datetime] = None


class TaskOut(BaseModel):
    id: int
    advisory_id: int
    assigned_to: int
    assigned_by: int
    title: str
    status: str
    due_date: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

# Permissions
class RolePermissionCreate(BaseModel):
    role: str
    feature: str
    is_allowed: bool

class RolePermissionOut(BaseModel):
    id: int
    role: str
    feature: str
    is_allowed: bool

    class Config:
        from_attributes = True

class RolePermissionUpdate(BaseModel):
    permissions: List[RolePermissionCreate]


# ── Media Hub ─────────────────────────────────────────────────────────────────
class MediaItemOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    url: str
    thumbnail_url: Optional[str]
    source_name: str
    media_type: str
    published_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True
