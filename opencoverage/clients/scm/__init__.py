from typing import Optional

from opencoverage.settings import Settings

from . import github  # noqa
from .base import SCMClient
from .github import Github
from .gitlab import Gitlab


def get_client(settings: Settings, installation_id: Optional[str]) -> SCMClient:
    if settings.scm == "gitlab":
        return Gitlab(settings, installation_id)
    elif settings.scm == "github":
        return Github(settings, installation_id)
    else:
        raise TypeError(
            f"Must provide valid SCM value, allowed: [github], provided: {settings.scm}"
        )
