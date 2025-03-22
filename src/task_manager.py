import asyncio
import random
import time
from loguru import logger
from utils.helpers import get_data_for_token
from src.functions import gaea_clicker_checkin, gaea_clicker_signin, gaea_clicker_aitrain, gaea_clicker_aicheckin, gaea_clicker_deeptrain, gaea_clicker_alltask

class TaskManager:
    def __init__(self, runname) -> None:
        self.datas = get_data_for_token(runname)
        self.count = len(self.datas)
        self.lock = asyncio.Lock()

    async def launch_clicker_checkin(self, thread: int, runid: int, module_name: str) -> None:
        while True:
            async with self.lock:
                if not self.datas:
                    return 'nokeys'
                else:
                    data = self.datas.pop(0)
                    id = self.count-len(self.datas)
            # Skip if runid is incorrect
            if runid > 0 and id != runid:
                continue

            parts = data.split(',')
            if len(parts) < 4:
                continue
            # logger.debug(f"parts: {parts}")
            userid=parts[0]
            email=parts[1]
            passwd=parts[2]
            prikey=parts[3]
            token=parts[4]
            proxy=parts[5]
            logger.info(f"userid: {userid} email: {email} proxy: {proxy}")

            result = await gaea_clicker_checkin(id, userid, email, passwd, prikey, token, proxy)
            if str(result).find("ERROR") > -1 and str(result).find("SUCCESS") == -1:
                logger.error(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_checkin result: {result}")
                break
            else:
                logger.success(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_checkin result: {result}")

            logger.info(f"thread: {thread} | Completed account usage - id: {id} userid: {userid} email: {email}")

    async def gaea_clicker_signin(self, thread: int, runid: int, module_name: str) -> None:
        while True:
            async with self.lock:
                if not self.datas:
                    return 'nokeys'
                else:
                    data = self.datas.pop(0)
                    id = self.count-len(self.datas)
            # Skip if runid is incorrect
            if runid > 0 and id != runid:
                continue

            parts = data.split(',')
            if len(parts) < 4:
                continue
            # logger.debug(f"parts: {parts}")
            userid=parts[0]
            email=parts[1]
            passwd=parts[2]
            prikey=parts[3]
            token=parts[4]
            proxy=parts[5]
            logger.info(f"userid: {userid} email: {email} proxy: {proxy}")

            result = await gaea_clicker_signin(id, userid, email, passwd, prikey, token, proxy)
            if str(result).find("ERROR") > -1 and str(result).find("SUCCESS") == -1:
                logger.error(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_signin result: {result}")
                break
            else:
                logger.success(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_signin result: {result}")

            logger.info(f"thread: {thread} | Completed account usage - id: {id} userid: {userid} email: {email}")

    async def launch_clicker_aitrain(self, thread: int, runid: int, module_name: str) -> None:
        while True:
            async with self.lock:
                if not self.datas:
                    return 'nokeys'
                else:
                    data = self.datas.pop(0)
                    id = self.count-len(self.datas)
            # Skip if runid is incorrect
            if runid > 0 and id != runid:
                continue

            parts = data.split(',')
            if len(parts) < 4:
                continue
            # logger.debug(f"parts: {parts}")
            userid=parts[0]
            email=parts[1]
            passwd=parts[2]
            prikey=parts[3]
            token=parts[4]
            proxy=parts[5]
            logger.info(f"userid: {userid} email: {email} proxy: {proxy}")

            result = await gaea_clicker_aitrain(id, userid, email, passwd, prikey, token, proxy)
            if str(result).find("ERROR") > -1 and str(result).find("SUCCESS") == -1:
                logger.error(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_aitrain result: {result}")
                break
            else:
                logger.success(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_aitrain result: {result}")

            logger.info(f"thread: {thread} | Completed account usage - id: {id} userid: {userid} email: {email}")

    async def launch_clicker_aicheckin(self, thread: int, runid: int, module_name: str) -> None:
        while True:
            async with self.lock:
                if not self.datas:
                    return 'nokeys'
                else:
                    data = self.datas.pop(0)
                    id = self.count-len(self.datas)
            # Skip if runid is incorrect
            if runid > 0 and id != runid:
                continue

            parts = data.split(',')
            if len(parts) < 4:
                continue
            # logger.debug(f"parts: {parts}")
            userid=parts[0]
            email=parts[1]
            passwd=parts[2]
            prikey=parts[3]
            token=parts[4]
            proxy=parts[5]
            logger.info(f"userid: {userid} email: {email} proxy: {proxy}")

            result = await gaea_clicker_aicheckin(id, userid, email, passwd, prikey, token, proxy)
            if str(result).find("ERROR") > -1 and str(result).find("SUCCESS") == -1:
                logger.error(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_aicheckin result: {result}")
                break
            else:
                logger.success(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_aicheckin result: {result}")

            logger.info(f"thread: {thread} | Completed account usage - id: {id} userid: {userid} email: {email}")

    async def launch_clicker_deeptrain(self, thread: int, runid: int, module_name: str) -> None:
        while True:
            async with self.lock:
                if not self.datas:
                    return 'nokeys'
                else:
                    data = self.datas.pop(0)
                    id = self.count-len(self.datas)
            # Skip if runid is incorrect
            if runid > 0 and id != runid:
                continue

            parts = data.split(',')
            if len(parts) < 4:
                continue
            # logger.debug(f"parts: {parts}")
            userid=parts[0]
            email=parts[1]
            passwd=parts[2]
            prikey=parts[3]
            token=parts[4]
            proxy=parts[5]
            logger.info(f"userid: {userid} email: {email} proxy: {proxy}")

            result = await gaea_clicker_deeptrain(id, userid, email, passwd, prikey, token, proxy)
            if str(result).find("ERROR") > -1 and str(result).find("SUCCESS") == -1:
                logger.error(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_deeptrain result: {result}")
                break
            else:
                logger.success(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_deeptrain result: {result}")

            logger.info(f"thread: {thread} | Completed account usage - id: {id} userid: {userid} email: {email}")

    async def launch_clicker_alltask(self, thread: int, runid: int, module_name: str) -> None:
        while True:
            async with self.lock:
                if not self.datas:
                    return 'nokeys'
                else:
                    data = self.datas.pop(0)
                    id = self.count-len(self.datas)
            # Skip if runid is incorrect
            if runid > 0 and id != runid:
                continue

            parts = data.split(',')
            if len(parts) < 4:
                continue
            # logger.debug(f"parts: {parts}")
            userid=parts[0]
            email=parts[1]
            passwd=parts[2]
            prikey=parts[3]
            token=parts[4]
            proxy=parts[5]
            logger.info(f"userid: {userid} email: {email} proxy: {proxy}")

            result = await gaea_clicker_alltask(id, userid, email, passwd, prikey, token, proxy)
            if str(result).find("ERROR") > -1 and str(result).find("SUCCESS") == -1:
                logger.error(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_alltask result: {result}")
                break
            else:
                logger.success(f"thread: {thread} id: {id} userid: {userid} email: {email} gaea_clicker_alltask result: {result}")

            logger.info(f"thread: {thread} | Completed account usage - id: {id} userid: {userid} email: {email}")
