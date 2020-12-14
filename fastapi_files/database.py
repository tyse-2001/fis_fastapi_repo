''' This is the database file '''

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "postgresql://postgres:03052001@localhost/postgres"

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker( # Database session
    autocommit = False,
    autoflush = False,
    bind = engine
)

Base = declarative_base()
