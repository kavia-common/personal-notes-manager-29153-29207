from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, EmailStr


# Auth / Tokens

class TokenResponse(BaseModel):
    """Token response for successful login"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type")


# Users

class UserCreateRequest(BaseModel):
    """Request model to register a new user"""
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=6, description="Plaintext password (min 6 chars)")


class UserResponse(BaseModel):
    """User response without sensitive fields"""
    id: int
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True


# Notes

class NoteCreateRequest(BaseModel):
    """Create note request"""
    title: str = Field(..., min_length=1, max_length=255)
    content: str = Field("", description="Note content")


class NoteUpdateRequest(BaseModel):
    """Update note request (partial)"""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    content: Optional[str] = Field(None)


class NoteResponse(BaseModel):
    """Note response model"""
    id: int
    title: str
    content: str
    user_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PaginatedNotesResponse(BaseModel):
    """Paginated response for notes listing"""
    items: List[NoteResponse]
    page: int
    page_size: int
    total: int
    has_more: bool
