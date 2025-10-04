from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Index
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    """
    User entity with unique email and hashed password.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    notes = relationship("Note", back_populates="owner", cascade="all, delete-orphan")


class Note(Base):
    """
    Note entity owned by a user with timestamps.
    """
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False, index=True)
    content = Column(Text, default="", nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = relationship("User", back_populates="notes")

    __table_args__ = (
        Index("ix_notes_user_title", "user_id", "title"),
    )
