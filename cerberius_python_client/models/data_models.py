from typing import List, Optional
from dataclasses import dataclass

@dataclass
class EmailData:
    comment: Optional[str] = None
    did_you_mean: Optional[str] = None
    domain: Optional[str] = None
    domain_ip: Optional[str] = None
    email_address: Optional[str] = None
    has_dmarc: Optional[bool] = None
    has_spf: Optional[bool] = None
    is_disposable: Optional[bool] = None
    is_free: Optional[bool] = None
    is_shared_address: Optional[bool] = None
    mx_hosts: Optional[str] = None
    mx_reverse_dns: Optional[str] = None
    smtp_catch_all: Optional[bool] = None
    smtp_valid: Optional[bool] = None
    user: Optional[str] = None
    validity_score: Optional[int] = None

@dataclass
class EmailLookupRequest:
    data: List[str]

@dataclass
class EmailLookupResponse:
    data: Optional[List[EmailData]] = None
    excess_charges_apply: Optional[bool] = None

@dataclass
class IPData:
    abuse_email: Optional[str] = None
    asn: Optional[str] = None
    city: Optional[str] = None
    continent_code: Optional[str] = None
    continent_name: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    currency: Optional[str] = None
    currencysymbol: Optional[str] = None
    fraud_score: Optional[str] = None
    in_eu: Optional[bool] = None
    ip_address: Optional[str] = None
    is_anonymous: Optional[bool] = None
    is_tor_exit_point: Optional[bool] = None
    isp: Optional[str] = None
    latitude: Optional[str] = None
    locale: Optional[str] = None
    longitude: Optional[str] = None
    lookup_status: Optional[str] = None
    on_block_list: Optional[bool] = None
    org_address: Optional[str] = None
    org_email: Optional[str] = None
    org_name: Optional[str] = None
    org_phone: Optional[str] = None
    recent_spam_domain: Optional[bool] = None
    remark: Optional[str] = None
    reverse_dns: Optional[str] = None
    timezone: Optional[str] = None
    timezone_offset: Optional[int] = None

@dataclass
class IPLookupRequest:
    data: List[str]

@dataclass
class IPLookupResponse:
    data: Optional[List[IPData]] = None
    excess_charges_apply: Optional[bool] = None

@dataclass
class Prompt:
    prompt: str

@dataclass
class PromptGuardData:
    comment: Optional[str] = None
    confidence_score: Optional[int] = None
    malicious: Optional[bool] = None

@dataclass
class PromptGuardRequest:
    data: Prompt # This should be a Prompt object, not a list.

@dataclass
class PromptGuardResponse:
    data: Optional[PromptGuardData] = None
    excess_charges_apply: Optional[bool] = None

@dataclass
class ErrorData:
    code: Optional[int] = None
    message: Optional[str] = None

@dataclass
class ErrorResponse:
    error: Optional[ErrorData] = None 