import os
import secrets
from datetime import timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.api.models import Base, User, Note
from src.api.database import engine, get_db
from src.api.auth import (
    create_access_token,
    get_password_hash,
    verify_password,
    get_current_user,
)
from src.api.schemas import (
    TokenResponse,
    UserCreateRequest,
    UserResponse,
    NoteCreateRequest,
    NoteUpdateRequest,
    NoteResponse,
    PaginatedNotesResponse,
)

# Initialize database tables
Base.metadata.create_all(bind=engine)

# Environment configuration
DEFAULT_SECRET = secrets.token_urlsafe(32)
SECRET_KEY = os.getenv("SECRET_KEY", DEFAULT_SECRET)
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

app = FastAPI(
    title="Notes API",
    description="Notes application backend API with JWT auth and CRUD for personal notes.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Health", "description": "Service health and status."},
        {"name": "Auth", "description": "User registration and authentication."},
        {"name": "Notes", "description": "CRUD operations for notes."},
    ],
)

# CORS setup - allow frontend
frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# PUBLIC_INTERFACE
@app.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """
    Health check endpoint.

    Returns:
        JSON object indicating service status.
    """
    return {"message": "Healthy"}


# Seed logic for dev convenience
def seed_demo_user(db: Session):
    """Create a demo user if none exist (dev only)."""
    if os.getenv("ENV", "dev") == "dev":
        has_user = db.query(User).first()
        if not has_user:
            email = "demo@example.com"
            pwd = "password123"
            user = User(email=email, password_hash=get_password_hash(pwd))
            db.add(user)
            db.commit()
            print(f"Seeded demo user: {email} / {pwd}")


# -------- Auth Routes --------

# PUBLIC_INTERFACE
@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Auth"],
    summary="Register a new user",
)
def register_user(payload: UserCreateRequest, db: Session = Depends(get_db)):
    """
    Register a new user.

    Body:
        email: valid email address
        password: plaintext password

    Returns:
        UserResponse without sensitive fields.

    Raises:
        400 if email already in use.
    """
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=payload.email, password_hash=get_password_hash(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserResponse(id=user.id, email=user.email, created_at=user.created_at)


# PUBLIC_INTERFACE
@app.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["Auth"],
    summary="Login and obtain JWT access token",
)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Login endpoint using OAuth2PasswordRequestForm fields.

    Form fields:
        username: email of the user
        password: plaintext password

    Returns:
        TokenResponse with access token and token type.

    Raises:
        401 on invalid credentials.
    """
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token({"sub": str(user.id)}, expires_delta=access_token_expires)
    return TokenResponse(access_token=token, token_type="bearer")


# -------- Notes Routes --------

# PUBLIC_INTERFACE
@app.get(
    "/notes",
    response_model=PaginatedNotesResponse,
    tags=["Notes"],
    summary="List notes with pagination and search",
)
def list_notes(
    page: int = Query(1, ge=1, description="Page number starting at 1"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    q: Optional[str] = Query(None, description="Search query for title/content"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List notes belonging to the current user, with optional text search and pagination.

    Query params:
        page: page number, >= 1
        page_size: page size, 1..100
        q: optional text to match in title or content

    Returns:
        PaginatedNotesResponse with items and pagination metadata.
    """
    query = db.query(Note).filter(Note.user_id == current_user.id)
    if q:
        like = f"%{q}%"
        query = query.filter((Note.title.ilike(like)) | (Note.content.ilike(like)))
    total = query.count()
    items = (
        query.order_by(Note.updated_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    notes = [
        NoteResponse(
            id=n.id,
            title=n.title,
            content=n.content,
            user_id=n.user_id,
            created_at=n.created_at,
            updated_at=n.updated_at,
        )
        for n in items
    ]
    return PaginatedNotesResponse(
        items=notes,
        page=page,
        page_size=page_size,
        total=total,
        has_more=(page * page_size) < total,
    )


# PUBLIC_INTERFACE
@app.post(
    "/notes",
    response_model=NoteResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Notes"],
    summary="Create a new note",
)
def create_note(
    payload: NoteCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create a new note for the authenticated user.

    Body:
        title: note title
        content: note content

    Returns:
        Created NoteResponse
    """
    note = Note(title=payload.title, content=payload.content, user_id=current_user.id)
    db.add(note)
    db.commit()
    db.refresh(note)
    return NoteResponse(
        id=note.id,
        title=note.title,
        content=note.content,
        user_id=note.user_id,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


# PUBLIC_INTERFACE
@app.get(
    "/notes/{note_id}",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Get a note by ID",
)
def get_note(
    note_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieve a single note by ID. Only the owner can access it.
    """
    note = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    return NoteResponse(
        id=note.id,
        title=note.title,
        content=note.content,
        user_id=note.user_id,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


# PUBLIC_INTERFACE
@app.put(
    "/notes/{note_id}",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Update a note by ID",
)
def update_note(
    payload: NoteUpdateRequest,
    note_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update a note. Only the owner can modify it.
    """
    note = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    if payload.title is not None:
        note.title = payload.title
    if payload.content is not None:
        note.content = payload.content
    db.add(note)
    db.commit()
    db.refresh(note)
    return NoteResponse(
        id=note.id,
        title=note.title,
        content=note.content,
        user_id=note.user_id,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


# PUBLIC_INTERFACE
@app.delete(
    "/notes/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Notes"],
    summary="Delete a note by ID",
)
def delete_note(
    note_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete a note. Only the owner can delete it.
    """
    note = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    db.delete(note)
    db.commit()
    return None


# Create demo user if none exist (dev only)
@app.on_event("startup")
def on_startup():
    with next(get_db()) as db:
        seed_demo_user(db)
