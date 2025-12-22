import asyncio
import random
import time
from loguru import logger
from utils.helpers import get_data_for_token
from src.functions import (
    gaea_clicker_dailycheckin,
    gaea_clicker_medalcheckin,
    gaea_clicker_aitrain,
    gaea_clicker_traincheckin,
    gaea_clicker_deeptrain,
    gaea_clicker_tickettrain,
    gaea_clicker_deepchoice,
    gaea_clicker_ticketchoice,
    gaea_clicker_alltask
)

class TaskManager:
    def __init__(self, runname) -> None:
        self.runname = runname
        self.datas = get_data_for_token(runname)
        self.count = len(self.datas)
        self.lock = asyncio.Lock()

    async def _launch_task(self, thread: int, runeq: list, module_name: str, task_function) -> None:
        while True:
            try:
                async with self.lock:
                    if not self.datas:
                        return 'nokeys'
                    else:
                        data = self.datas.pop(0)
                        id = self.count - len(self.datas)
                # Skip if runeq is incorrect
                if len(runeq) > 0 and id not in runeq:
                    continue

                parts = data.split(',')
                if len(parts) < 4:
                    continue
                email, passwd, userid, token, prikey, proxy = map(str.strip, parts)
                logger.info(f"thread: {thread} id: {id} userid: {userid} email: {email} proxy: {proxy}")
                # email=parts[0].strip()
                # passwd=parts[1].strip()
                # userid=parts[2].strip()
                # token=parts[3].strip()
                # prikey=parts[4].strip()
                # proxy=parts[5].strip()

                result = await task_function(self.runname, id, userid, email, passwd, prikey, token, proxy)
                if str(result).find("ERROR") > -1:
                    logger.error(f"thread: {thread} id: {id} userid: {userid} email: {email} {module_name} result: {result}")
                    continue
                else:
                    logger.success(f"thread: {thread} id: {id} userid: {userid} email: {email} {module_name} result: {result}")

                logger.info(f"thread: {thread} id: {id} userid: {userid} email: {email} | Completed account usage")
            except Exception as e:
                logger.error(f"An error occurred in {module_name}: {e}")
                time.sleep(60)

    async def launch_clicker_dailycheckin(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_dailycheckin)

    async def launch_clicker_medalcheckin(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_medalcheckin)

    async def launch_clicker_aitrain(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_aitrain)

    async def launch_clicker_deeptrain(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_deeptrain)

    async def launch_clicker_tickettrain(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_tickettrain)

    async def launch_clicker_traincheckin(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_traincheckin)

    async def launch_clicker_deepchoice(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_deepchoice)

    async def launch_clicker_ticketchoice(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_ticketchoice)

    async def launch_clicker_alltask(self, thread: int, runeq: list, module_name: str) -> None:
        await self._launch_task(thread, runeq, module_name, gaea_clicker_alltask)
