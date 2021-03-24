import asyncio
import logging
import pickle
import traceback
import schedule
from typing import (
    Any,
    Dict,
    Optional,
    Tuple,
    Type,
)

import pydantic

from opencoverage.database import Database

from .models import Task
from .settings import Settings

logger = logging.getLogger(__name__)
_registered: Dict[str, Tuple[Any, Type[pydantic.BaseModel]]] = {}


def register(name: str, func: Any, config: Type[pydantic.BaseModel]):
    _registered[name] = (func, config)


class InvalidTaskException(Exception):
    ...


class GitlabSchedule:
    """
    The purpose of tasks are to store task data in the database and
    to be able to run jobs based on that task data
    """

    check_interval = 1

    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self.consume_task = None
        self._schedule_status = False

    async def add(self, *, name: str, config: pydantic.BaseModel) -> None:
        if name not in _registered:
            raise InvalidTaskException(f"Task is not registered: {name}")
        _, config_type = _registered[name]
        if not isinstance(config, config_type):
            raise InvalidTaskException(f"Invalid task config: {name}: {config}")
        await self.db.add_task(name=name, data=pickle.dumps(config), status="scheduled")

    async def start_schedule(self) -> None:
        schedule.every(1).minutes.do(job)
        self._schedule_status = True

    async def stop_schedule(self) -> None:
        self._schedule_status = False


    async def run_tasks(self) -> None:
        while self._schedule_status:
            try:
                schedule.run_pending()
                await asyncio.sleep(self.check_interval)
            except (RuntimeError, asyncio.CancelledError):  # pragma: no cover
                return
            except Exception:
                logger.exception(
                    "Unhandled error running tasks, trying again", exc_info=True
                )
                await asyncio.sleep(1)


    async def run_task(self, task: Task) -> None:
        cursor, reports = await db.get_reports(status=1)
        for report in reports:
            result.append(_format_report(report))
