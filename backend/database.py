import os
import time
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
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

    raw_host = os.getenv("DB_HOST", "127.0.0.1")
    # Prefer explicit IPv4 address to avoid dual-stack IPv6/IPv4 connection timeout on Windows
    db_host = "127.0.0.1" if raw_host in ("localhost", "127.0.0.1") else raw_host

    DATABASE_URL = URL.create(
        drivername="postgresql+psycopg2",
        username=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres123"),
        host=db_host,
        port=db_port,
        database=os.getenv("DB_NAME", "cyber_digital_twin"),
    )

engine_kwargs = {}
if str(DATABASE_URL).startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
elif "postgresql" in str(DATABASE_URL):
    engine_kwargs["connect_args"] = {"connect_timeout": 1}

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

_db_status_cache = {"online": None, "last_checked": 0.0}

def is_database_online() -> bool:
    """
    Check if the configured database engine is reachable.
    Caches the status (30s when offline, 5s when online) to ensure
    sub-second startup for offline local environments.
    """
    now = time.time()
    cache_ttl = 5.0 if _db_status_cache["online"] else 30.0
    if _db_status_cache["online"] is not None and (now - _db_status_cache["last_checked"]) < cache_ttl:
        return bool(_db_status_cache["online"])

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        _db_status_cache["online"] = True
    except Exception:
        _db_status_cache["online"] = False
    _db_status_cache["last_checked"] = now
    return bool(_db_status_cache["online"])
