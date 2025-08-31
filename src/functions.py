import os
import platform
from src.gaea_client import GaeaClient
from src.gaea_dailytask import GaeaDailyTask

# gaea

async def gaea_clicker_register(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-register")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_register()

async def gaea_clicker_login(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-login")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_login()

async def gaea_clicker_session(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-session")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_session()

async def gaea_clicker_earninfo(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-earninfo")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_earninfo()

async def gaea_clicker_godhoodinfo(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodinfo")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodinfo()

async def gaea_clicker_era3info(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-era3info")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_era3info()

async def gaea_clicker_openblindbox(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-blindbox")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_openblindbox()

async def gaea_clicker_referralreword(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-referralreword")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_referralreword()

async def gaea_clicker_bindaddress(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-bindaddress")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_bindaddress()

async def gaea_clicker_invitereward(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-invitereward")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_invitereward()

async def gaea_clicker_inviteclaimed(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-inviteclaimed")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_inviteclaimed()

async def gaea_clicker_emotionreward(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-emotionreward")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_emotionreward()

async def gaea_clicker_emotionclaimed(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-emotionclaimed")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_emotionclaimed()

async def gaea_clicker_mintnft(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-mintnft")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_mintnft()

async def gaea_clicker_nftinfo(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-mintnft")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_nftinfo()


async def gaea_clicker_nftoblate(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-mintnft")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_nftoblate()


# async def gaea_clicker_upgradenft(runname, id, userid, email, passwd, prikey, token, proxy):
#     if platform.system().lower() == 'windows':
#         os.system("title gaea-upgradenft")
#     daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
#     return await daily_task.daily_clicker_upgradenft()

async def gaea_clicker_godhoodid(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodid")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodid()

async def gaea_clicker_godhoodemotion(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodemotion")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodemotion()

async def gaea_clicker_checkin(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-checkin")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_checkin()

async def gaea_clicker_signin(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-signin")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_signin()

async def gaea_clicker_dailycheckin(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-dailycheckin")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_dailycheckin()

async def gaea_clicker_medalcheckin(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-medalcheckin")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_medalcheckin()

async def gaea_clicker_aitrain(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-aitrain")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_aitrain()

async def gaea_clicker_aicheckin(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-aicheckin")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_aicheckin()

async def gaea_clicker_deeptrain(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-deeptrain")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_deeptrain()

async def gaea_clicker_tickettrain(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-tickettrain")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_tickettrain()

async def gaea_clicker_alltask(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-alltask")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_alltask()
