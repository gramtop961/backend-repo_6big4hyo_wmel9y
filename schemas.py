"""
Database Schemas for MagicFix Pro

Each Pydantic model represents a MongoDB collection. Collection name is the lowercase class name.
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

Role = Literal["customer", "engineer", "admin"]
JobStatus = Literal[
    "requested",
    "matched",
    "accepted",
    "en_route",
    "in_progress",
    "completed",
    "paid",
    "reviewed",
]
CallDirection = Literal["customer_to_engineer", "engineer_to_customer"]
PaymentProvider = Literal["paystack", "stripe"]

class User(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    role: Role = "customer"
    password_hash: str
    is_verified: bool = False
    avatar_url: Optional[str] = None
    rating_avg: float = 0.0
    rating_count: int = 0

class EngineerProfile(BaseModel):
    user_id: str
    skills: List[str] = []
    bio: Optional[str] = None
    certifications: List[str] = []
    id_docs: List[str] = []
    is_approved: bool = False
    availability: List[str] = []  # e.g., ["mon-morning", "tue-afternoon"]
    location: Optional[str] = None

class ServiceCategory(BaseModel):
    key: str
    name: str
    icon: Optional[str] = None
    active: bool = True

class Job(BaseModel):
    customer_id: str
    engineer_id: Optional[str] = None
    category_key: str
    description: str
    photos: List[str] = []
    location_text: Optional[str] = None
    status: JobStatus = "requested"
    price_estimate: Optional[float] = None
    rating: Optional[int] = None
    review: Optional[str] = None

class Message(BaseModel):
    job_id: str
    sender_id: str
    receiver_id: str
    text: Optional[str] = None
    image_url: Optional[str] = None
    audio_url: Optional[str] = None
    seen: bool = False

class CallLog(BaseModel):
    job_id: str
    caller_id: str
    callee_id: str
    direction: CallDirection
    room_id: str
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_sec: Optional[int] = None
    accepted: bool = False
    network_quality: Optional[str] = None

class Payment(BaseModel):
    job_id: str
    customer_id: str
    engineer_id: str
    amount: float
    currency: str = "NGN"
    provider: PaymentProvider = "paystack"
    provider_ref: Optional[str] = None
    status: Literal["init", "succeeded", "failed"] = "init"
    commission: float = 0.15  # 15%

class Notification(BaseModel):
    user_id: str
    title: str
    body: str
    type: str
    data: Optional[dict] = None
    seen: bool = False
