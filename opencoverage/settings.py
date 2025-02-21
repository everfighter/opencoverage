from typing import List, Optional

from pydantic import BaseSettings


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    timeout_keep_alive: int = 10
    proxy_headers: bool = True
    root_path: str = ""

    public_url: Optional[str] = "https://open-coverage.org/api"

    dsn: str

    cors: List[str] = []

    scm: str
    gitlab_app_id: Optional[str]
    gitlab_app_pem_file: Optional[str]
    gitlab_default_installation_id: Optional[str]
    github_app_id: Optional[str]
    github_app_pem_file: Optional[str]
    github_default_installation_id: Optional[str]
