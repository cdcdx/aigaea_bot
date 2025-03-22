import os
import platform
from src.gaea_client import GaeaClient
from src.gaea_dailytask import GaeaDailyTask

# gaea
async def gaea_clicker_checkin(id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-checkin")
    daily_task = GaeaDailyTask(GaeaClient(id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_checkin()

async def gaea_clicker_signin(id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-signin")
    daily_task = GaeaDailyTask(GaeaClient(id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_signin()

async def gaea_clicker_aitrain(id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-aitrain")
    daily_task = GaeaDailyTask(GaeaClient(id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_aitrain()

async def gaea_clicker_aicheckin(id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-aicheckin")
    daily_task = GaeaDailyTask(GaeaClient(id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_aicheckin()

async def gaea_clicker_deeptrain(id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-deeptrain")
    daily_task = GaeaDailyTask(GaeaClient(id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_deeptrain()

async def gaea_clicker_alltask(id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-alltask")
    daily_task = GaeaDailyTask(GaeaClient(id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_alltask()
