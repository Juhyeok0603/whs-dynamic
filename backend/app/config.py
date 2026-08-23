from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path(os.getenv("DATA_DIR", "data/analyses"))
    samples_dir: Path = Path(os.getenv("SAMPLES_DIR", "samples"))
    network_mode: str = os.getenv("NETWORK_MODE", "restricted")
    sandbox_runtime: str = os.getenv("SANDBOX_RUNTIME", "runsc")
    gvisor_log_dir: Path = Path(os.getenv("GVISOR_LOG_DIR", "/var/log/runsc"))
    total_timeout: int = int(os.getenv("TOTAL_TIMEOUT", "240"))
    max_output_bytes: int = int(os.getenv("MAX_OUTPUT_BYTES", "65536"))
    max_import_targets: int = int(os.getenv("MAX_IMPORT_TARGETS", "10"))
    vt_api_key: str | None = os.getenv("VT_API_KEY") or None
    top_packages_cache_ttl_hours: int = int(os.getenv("TOP_PACKAGES_CACHE_TTL_HOURS", "168"))
    whois_timeout: int = int(os.getenv("WHOIS_TIMEOUT", "5"))

    def validate(self) -> None:
        if self.network_mode not in {"disabled", "restricted", "full"}:
            raise ValueError("NETWORK_MODE must be disabled, restricted, or full")


settings = Settings()
