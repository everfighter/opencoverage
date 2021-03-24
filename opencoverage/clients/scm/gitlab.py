import time
from datetime import datetime, timedelta, timezone
from typing import (
    Any,
    AsyncIterator,
    Dict,
    List,
    Optional,
    cast,
)

import aiohttp_client
import jwt
import pydantic
from cryptography.hazmat.backends import default_backend

from opencoverage.settings import Settings
from opencoverage.types import Pull

from .base import SCMClient
from .exceptions import (
    APIException,
    AuthorizationException,
    InstallationException,
    NotFoundException,
)


class GitlabUser(pydantic.BaseModel):
    name: str
    id: int
    avatar_url: str
    username: str
    web_url: str
    state: str
    # site_admin: bool


class GitlabRepo(pydantic.BaseModel):
    id: int
    name: str
    full_name: str
    private: bool
    owner: GitlabUser
    description: Optional[str]
    fork: bool
    url: str
    created_at: str
    updated_at: str


class GitlabRef(pydantic.BaseModel):
    label: str
    ref: str
    sha: str
    user: GitlabUser
    repo: GitlabRepo


class GitlabPull(pydantic.BaseModel):
    web_url: str
    id: str
    # diff_url: str
    # patch_url: str
    # number: int
    state: str
    title: Optional[str]
    author: GitlabUser
    created_at: str
    updated_at: str
    closed_at: Optional[str]
    merged_at: Optional[str]
    merge_commit_sha: str
    assignee: Optional[GitlabUser]
    assignees: List[GitlabUser]
    reviewers: List[GitlabUser]
    # draft: bool
    commits_url: str
    target_branch: str
    source_branch: str
# {
#     "id": 1,
#     "iid": 1,
#     "project_id": 3,
#     "title": "test1",
#     "description": "fixed login page css paddings",
#     "state": "merged",
#     "merged_by": {
#       "id": 87854,
#       "name": "Douwe Maan",
#       "username": "DouweM",
#       "state": "active",
#       "avatar_url": "https://gitlab.example.com/uploads/-/system/user/avatar/87854/avatar.png",
#       "web_url": "https://gitlab.com/DouweM"
#     },
#     "merged_at": "2018-09-07T11:16:17.520Z",
#     "closed_by": null,
#     "closed_at": null,
#     "created_at": "2017-04-29T08:46:00Z",
#     "updated_at": "2017-04-29T08:46:00Z",
#     "target_branch": "master",
#     "source_branch": "test1",
#     "upvotes": 0,
#     "downvotes": 0,
#     "author": {
#       "id": 1,
#       "name": "Administrator",
#       "username": "admin",
#       "state": "active",
#       "avatar_url": null,
#       "web_url" : "https://gitlab.example.com/admin"
#     },
#     "assignee": {
#       "id": 1,
#       "name": "Administrator",
#       "username": "admin",
#       "state": "active",
#       "avatar_url": null,
#       "web_url" : "https://gitlab.example.com/admin"
#     },
#     "assignees": [{
#       "name": "Miss Monserrate Beier",
#       "username": "axel.block",
#       "id": 12,
#       "state": "active",
#       "avatar_url": "http://www.gravatar.com/avatar/46f6f7dc858ada7be1853f7fb96e81da?s=80&d=identicon",
#       "web_url": "https://gitlab.example.com/axel.block"
#     }],
#     "reviewers": [{
#       "id": 2,
#       "name": "Sam Bauch",
#       "username": "kenyatta_oconnell",
#       "state": "active",
#       "avatar_url": "https://www.gravatar.com/avatar/956c92487c6f6f7616b536927e22c9a0?s=80&d=identicon",
#       "web_url": "http://gitlab.example.com//kenyatta_oconnell"
#     }],
#     "source_project_id": 2,
#     "target_project_id": 3,
#     "labels": [
#       "Community contribution",
#       "Manage"
#     ],
#     "work_in_progress": false,
#     "milestone": {
#       "id": 5,
#       "iid": 1,
#       "project_id": 3,
#       "title": "v2.0",
#       "description": "Assumenda aut placeat expedita exercitationem labore sunt enim earum.",
#       "state": "closed",
#       "created_at": "2015-02-02T19:49:26.013Z",
#       "updated_at": "2015-02-02T19:49:26.013Z",
#       "due_date": "2018-09-22",
#       "start_date": "2018-08-08",
#       "web_url": "https://gitlab.example.com/my-group/my-project/milestones/1"
#     },
#     "merge_when_pipeline_succeeds": true,
#     "merge_status": "can_be_merged",
#     "sha": "8888888888888888888888888888888888888888",
#     "merge_commit_sha": null,
#     "squash_commit_sha": null,
#     "user_notes_count": 1,
#     "discussion_locked": null,
#     "should_remove_source_branch": true,
#     "force_remove_source_branch": false,
#     "allow_collaboration": false,
#     "allow_maintainer_to_push": false,
#     "web_url": "http://gitlab.example.com/my-group/my-project/merge_requests/1",
#     "references": {
#       "short": "!1",
#       "relative": "my-group/my-project!1",
#       "full": "my-group/my-project!1"
#     },
#     "time_stats": {
#       "time_estimate": 0,
#       "total_time_spent": 0,
#       "human_time_estimate": null,
#       "human_total_time_spent": null
#     },
#     "squash": false,
#     "task_completion_status":{
#       "count":0,
#       "completed_count":0
#     }
#   }

class GitlabCheckOutput(pydantic.BaseModel):
    title: Optional[str]
    summary: Optional[str]
    text: Optional[str]
    annotations_count: int
    annotations_url: Optional[str]


class GitlabApp(pydantic.BaseModel):
    created_at: datetime
    description: Optional[str]
    external_url: str
    id: int
    name: str


class GitlabCheck(pydantic.BaseModel):
    id: int
    head_sha: str
    node_id: Optional[str]
    external_id: Optional[str]
    url: Optional[str]
    html_url: Optional[str]
    details_url: Optional[str]
    status: str
    conclusion: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]
    name: str

    app: Optional[GitlabApp]


class GitlabChecks(pydantic.BaseModel):
    check_runs: List[GitlabCheck]
    total_count: int


class GitlabAccessData(pydantic.BaseModel):
    token: str
    expires_at: datetime
    permissions: Dict[str, str]
    repository_selection: str


class GitlabComment(pydantic.BaseModel):
    id: int
    body: str
    user: Optional[GitlabUser]


# class GitlabInstallation(pydantic.BaseModel):
#     account: Optional[GitlabUser]
#     app_id: int
#     app_slug: str
#     created_at: str
#     id: int
#     permissions: Dict[str, str]
#     suspended_at: Optional[str]
#     suspended_by: Optional[str]
#     target_id: Optional[int]
#     target_type: Optional[str]
#     updated_at: Optional[str]


GITHUB_API_URL = "https://api.gitlab.com"


class Token(pydantic.BaseModel):
    jwt_token: str
    jwt_expiration: int
    access_data: Optional[GitlabAccessData]


class Permissions:
    WRITE = "write"
    READ = "read"


# this should
_token_cache: Dict[str, Token] = {}
_private_key_cache = {}


class Gitlab(SCMClient):
    _required_permissions = {
        "checks": Permissions.WRITE,
        "contents": Permissions.WRITE,
        "issues": Permissions.WRITE,
        "metadata": Permissions.READ,
        "pull_requests": Permissions.WRITE,
        "statuses": Permissions.READ,
    }

    def __init__(self, settings: Settings, installation_id: Optional[str]):
        super().__init__(settings, installation_id)
        self.installation_id = cast(
            str, installation_id or settings.gitlab_default_installation_id
        )
        if settings.gitlab_app_pem_file is None:
            raise TypeError("Must configure gitlab_app_pem_file")
        #if settings.gitlab_app_pem_file not in _private_key_cache:
        #    with open(settings.gitlab_app_pem_file, "rb") as fi:
        #        _private_key_cache[
        #            settings.gitlab_app_pem_file
        #        ] = default_backend().load_pem_private_key(fi.read(), None)
        #self._private_key = _private_key_cache[settings.gitlab_app_pem_file]
        self._private_key = ""

    # def _get_jwt_token(self) -> str:
    #     time_since_epoch_in_seconds = int(time.time())
    #     token_data = _token_cache.get(self.installation_id)
    #     if token_data is None or token_data.jwt_expiration < (
    #         time_since_epoch_in_seconds - 10
    #     ):
    #         jwt_expiration = time_since_epoch_in_seconds + (2 * 60)
    #         _token_cache[self.installation_id] = Token(
    #             jwt_expiration=jwt_expiration,
    #             jwt_token=jwt.encode(
    #                 {
    #                     # issued at time
    #                     "iat": time_since_epoch_in_seconds,
    #                     # JWT expiration time (10 minute maximum)
    #                     "exp": jwt_expiration,
    #                     # GitHub App's identifier
    #                     "iss": self.settings.gitlab_app_id,
    #                 },
    #                 self._private_key,
    #                 algorithm="RS256",
    #             ),
    #         )
    #     return _token_cache[self.installation_id].jwt_token

    async def get_access_token(self) -> str:
        return "TxeACPEtQAeHP-1vsUw7"
        token_data = _token_cache.get(self.installation_id)

        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if (
            token_data is None
            or token_data.access_data is None
            or token_data.access_data.expires_at < (now - timedelta(minutes=2))
        ):
            url = (
                f"{GITHUB_API_URL}/app/installations/{self.installation_id}/access_tokens"
            )
            jwt_token = self._get_jwt_token()
            async with aiohttp_client.post(
                url,
                headers={
                    "Accepts": "application/vnd.gitlab.v3+json",
                    "Authorization": f"Bearer {jwt_token}",
                },
            ) as resp:
                if resp.status != 201:
                    text = await resp.text()
                    raise APIException(
                        f"Could not authenticate with pem: {resp.status}: {text}"
                    )
                data = await resp.json()
                access_data = GitlabAccessData.parse_obj(data)
                _token_cache[self.installation_id].access_data = access_data
            return access_data.token
        else:
            return token_data.access_data.token

    async def _prepare_request(
        self,
        *,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
    ):
        func = getattr(aiohttp_client, method.lower())
        headers = headers or {}
        token = await self.get_access_token()
        headers["Content-Type"] = "application/json"
        headers["PRIVATE-TOKEN"] = token
        return func(url, headers=headers, params=params or {}, json=json)

    # async def validate(self) -> None:
    #     # Check the installation is correctly working
    #     return
    #     url = f"{GITHUB_API_URL}/app/installations/{self.installation_id}"
    #     jwt_token = self._get_jwt_token()
    #     async with aiohttp_client.get(
    #         url,
    #         headers={
    #             "Accepts": "application/vnd.gitlab.v3+json",
    #             "Authorization": f"Bearer {jwt_token}",
    #         },
    #     ) as resp:
    #         if resp.status != 200:
    #             text = await resp.text()
    #             raise AuthorizationException(
    #                 f"Invalid request from configuration application: {resp.status}: {text}"
    #             )
    #         install = GitlabInstallation.parse_obj(await resp.json())
    #         missing_perms = []
    #         for name, lvl in self._required_permissions.items():
    #             install_lvl = install.permissions.get(name)
    #             if install_lvl is None or (
    #                 install_lvl != lvl and install_lvl != Permissions.WRITE
    #             ):
    #                 missing_perms.append((name, lvl))
    #         if len(missing_perms) > 0:
    #             raise InstallationException(
    #                 f"Applicaiton missing required permissions: {missing_perms}"
    #             )

    async def get_pulls(self, project_id: int, repo: str, commit_hash: str) -> List[Pull]:
        url = f"{GITLAB_API_URL}//projects/{project_id}/repository/commits/{commit_hash}/merge_requests"
        async with await self._prepare_request(
            url=url,
            method="get",
        ) as resp:
            if resp.status == 422:
                # no pulls found
                return []
            if resp.status == 401:
                text = await resp.json()
                raise AuthorizationException(f"API Unauthorized: {text}")

            data = await resp.json()
            pulls = []
            for item in data:
                gpull = GitlabPull.parse_obj(item)
                pulls.append(
                    Pull(base=gpull.source_branch, head=gpull.target_branch, id=gpull.id)
                )
        return pulls

    async def get_pull_diff(self, project_id: int, repo: str, id: int) -> str:
        url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{id}/changes"
        async with await self._prepare_request(
            url=url,
            method="get",
        ) as resp:
            if resp.status == 401:
                text = await resp.json()
                raise AuthorizationException(f"API Unauthorized: {text}")
            data = await resp.text(encoding="latin-1")
        return data

    # async def create_check(
    #     self,
    #     org: str,
    #     repo: str,
    #     commit: str,
    #     details_url: Optional[str] = None,
    # ) -> str:
    #     url = f"{GITHUB_API_URL}/repos/{org}/{repo}/check-runs"
    #     async with await self._prepare_request(
    #         url=url,
    #         method="post",
    #         headers={"Accept": "application/vnd.gitlab.v3+json"},
    #         json={
    #             "head_sha": commit,
    #             "name": "coverage",
    #             "status": "in_progress",
    #             "details_url": details_url or self.settings.public_url,
    #             "output": {
    #                 "title": "Open Coverage: Running",
    #                 "summary": "Recording and checking coverage data",
    #             },
    #         },
    #     ) as resp:
    #         if resp.status != 201:
    #             text = await resp.text()
    #             raise AuthorizationException(
    #                 f"Error creating check: {resp.status}: {text}"
    #             )
    #         check = GitlabCheck.parse_obj(await resp.json())
    #         return str(check.id)

    # async def update_check(
    #     self,
    #     org: str,
    #     repo: str,
    #     check_id: str,
    #     running: bool = False,
    #     success: bool = False,
    #     text: Optional[str] = None,
    # ) -> None:
    #     url = f"{GITHUB_API_URL}/repos/{org}/{repo}/check-runs/{check_id}"
    #     if success:
    #         conclusion = "success"
    #     else:
    #         conclusion = "failure"
    #     if running:
    #         status = "in_progress"
    #     else:
    #         status = "completed"

    #     if text is None:
    #         text = "Successful"

    #     async with await self._prepare_request(
    #         url=url,
    #         method="patch",
    #         headers={"Accept": "application/vnd.gitlab.v3+json"},
    #         json={
    #             "status": status,
    #             "conclusion": conclusion,
    #             "output": {
    #                 "title": text,
    #                 "summary": "Recording and checking coverage data",
    #             },
    #         },
    #     ) as resp:
    #         if resp.status != 200:
    #             text = await resp.text()
    #             raise APIException(f"Error update check: {resp.status}: {text}")

    # async def create_comment(self, org: str, repo: str, pull_id: int, text: str) -> str:
    #     url = f"{GITHUB_API_URL}/repos/{org}/{repo}/issues/{pull_id}/comments"
    #     async with await self._prepare_request(
    #         url=url,
    #         method="post",
    #         headers={"Accept": "application/vnd.gitlab.v3+json"},
    #         json={"body": text},
    #     ) as resp:
    #         if resp.status != 201:
    #             text = await resp.text()
    #             raise APIException(f"Error update check: {resp.status}: {text}")
    #         ob = GitlabComment.parse_obj(await resp.json())
    #         return str(ob.id)

    # async def update_comment(
    #     self, org: str, repo: str, comment_id: str, text: str
    # ) -> None:
    #     url = f"{GITHUB_API_URL}/repos/{org}/{repo}/issues/comments/{comment_id}"
    #     async with await self._prepare_request(
    #         url=url,
    #         method="patch",
    #         headers={"Accept": "application/vnd.gitlab.v3+json"},
    #         json={"body": text},
    #     ) as resp:
    #         if resp.status != 200:
    #             text = await resp.text()
    #             raise APIException(f"Error update check: {resp.status}: {text}")

    async def getCompareInfosFromGitlab(self, project_id, forward_commit, previos):
        path = "projects/%s/repository/compare?from=%s&to=%s" % (project_id, forward_commit, previos)
        return self.requestToGitlab(path)

    async def getCommitInfoFromGitlab(self, project_id, commit):
        path = "projects/%s/repository/commits/%s" % (project_id, commit)
        return self.requestToGitlab(path)

    async def getAllCommitsFromGitlab(self, project_id):
        commits = []
        page_id = 1
        while page_id:
            path = "projects/%s/repository/commits?all=true&per_page=50&page=%s" % (
                project_id, page_id)
            resp = self.requestToGitlab(path)
            if resp and resp.status_code == 200:
                commits.extend(json.loads(resp.text))
                page_id = resp.headers["X-Next-Page"]
            else:
                break
        return commits
    
    async def requestToGitlab(self, path, params={}):
        url = "%s%s" % (GITLAB_API_URL, path)
        headers = {
            "Content-Type": "application/json",
            "PRIVATE-TOKEN": Authorization.gitlab_access_token
        }
        async with await requests.self._prepare_request((url, method="get",headers=headers, params=params) as resp:
        # print resp
            if resp and resp.status_code in [200, 201]:
                self.request.logger.info(
                    "gitlab GET request %s send success with status code %s" %
                    (url, resp.status_code))
                return resp
            elif resp.status_code == 404:
                self.request.logger.warning(
                    "gitlab GET request %s send fail with status code %s" %
                    (url, resp.status_code))
                return resp
            else:
                self.request.logger.warning(
                    "gitlab GET request %s send fail with status code %s" %
                    (url, resp.status_code))
                return None

    async def file_exists(self, org: str, repo: str, commit: str, filename: str) -> bool:
        url = f"{GITHUB_API_URL}/repos/{org}/{repo}/contents/{filename}"
        async with await self._prepare_request(
            url=url,
            method="get",
            params={"ref": commit},
        ) as resp:
            if resp.status == 401:
                text = await resp.json()
                raise AuthorizationException(f"API Unauthorized: {text}")
            if resp.status == 404:
                return False
            return True

    async def download_file(
        self, org: str, repo: str, commit: str, filename: str
    ) -> AsyncIterator[bytes]:
        url = f"{GITHUB_API_URL}/repos/{org}/{repo}/contents/{filename}"
        async with await self._prepare_request(
            url=url,
            method="get",
            params={"ref": commit},
            headers={"Accept": "application/vnd.gitlab.v3.raw"},
        ) as resp:
            if resp.status == 401:
                text = await resp.json()
                raise AuthorizationException(f"API Unauthorized: {text}")
            if resp.status == 404:
                text = await resp.json()
                raise NotFoundException(f"File not found: {text}")
            while chunk := await resp.content.read(1024):
                yield chunk
