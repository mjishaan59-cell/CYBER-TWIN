import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

load_dotenv(override=False)
if os.path.exists("/root/cyber-digital-twin/.env"):
    load_dotenv(dotenv_path="/root/cyber-digital-twin/.env", override=False)

database_url_env = os.getenv("DATABASE_URL")
if database_url_env:
    DATABASE_URL = database_url_env
else:
    db_port_raw = os.getenv("DB_PORT", "5432")
    try:
        db_port = int(db_port_raw) if db_port_raw else 5432
    except ValueError:
        db_port = 5432

    DATABASE_URL = URL.create(
        drivername="postgresql+psycopg2",
        username=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres123"),
        host=os.getenv("DB_HOST", "localhost"),
        port=db_port,
        database=os.getenv("DB_NAME", "cyber_digital_twin"),
    )

engine_kwargs = {}
if str(DATABASE_URL).startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
elif "postgresql" in str(DATABASE_URL):
    engine_kwargs["connect_args"] = {"connect_timeout": 2}

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
