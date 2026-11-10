import os
from dotenv import load_dotenv

load_dotenv(override=True)

HOSTS = [
    {
        "name": "localhost",
        "display_name": "Local Host (This Computer - Live)",
        "host": "127.0.0.1",
        "username": "local",
        "auth_method": "local",
        "is_local": True,
    },
    {
        "name": "prac-server",
        "display_name": "Remote Practice VM (Optional)",
        "host": os.getenv("HOST", "192.168.38.145"),
        "username": os.getenv("USERNAME", "root"),
        "password": os.getenv("PASSWORD", ""),
        "auth_method": "password",
        "is_local": False,
    },
]
