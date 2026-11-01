"""Input validation models used by the JSON API."""

from datetime import date
import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["Critical", "High", "Medium", "Low", "Unknown"]
FindingStatus = Literal["Open", "In Progress", "Resolved"]


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    ip_address: str = Field(min_length=2, max_length=64)
    hostname: str | None = Field(default=None, max_length=253)
    operating_system: str | None = Field(default=None, max_length=160)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as error:
            raise ValueError("Enter a valid IPv4 or IPv6 address.") from error


class AssetUpdate(AssetCreate):
    """Complete editable asset fields; IP addresses remain validated."""


class FindingCreate(BaseModel):
    cve_id: str = Field(min_length=1, max_length=32, pattern=r"^(CVE-\d{4}-\d{4,})$", description="CVE identifier")
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=12000)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: Severity = "Unknown"
    asset_id: int = Field(gt=0)
    status: FindingStatus = "Open"
    discovered_date: date = Field(default_factory=date.today)
    remediation_notes: str = Field(default="", max_length=12000)
    verified: bool = False


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    remediation_notes: str | None = Field(default=None, max_length=12000)
    verified: bool | None = None

