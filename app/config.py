from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    app_name: str = "Basic Network Sniffer"
    app_version: str = "0.1.0"
    data_dir: Path = Path(__file__).resolve().parent.parent / "data"
    capture_limit: int = 1000
    max_queue_size: int = 5000


settings = Settings()
