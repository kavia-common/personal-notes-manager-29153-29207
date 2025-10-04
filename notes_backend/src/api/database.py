import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Use SQLite file by default; can be overridden by DATABASE_URL env
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./notes.db")

# SQLite needs check_same_thread=False for multithreading in FastAPI
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """
    Dependency that provides a database session and ensures proper cleanup.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
