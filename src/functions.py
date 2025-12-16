import os
import platform
from src.gaea_client import GaeaClient
from src.gaea_dailytask import GaeaDailyTask

# gaea

## 过期任务
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

async def gaea_clicker_referralreword(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-referralreword")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_referralreword()

## 基础任务
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

async def gaea_clicker_era3info(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-era3info")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_era3info()

async def gaea_clicker_bindaddress(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-bindaddress")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_bindaddress()

async def gaea_clicker_openblindbox(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-openblindbox")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_openblindbox()

async def gaea_clicker_buytickets(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-buytickets")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_buytickets()

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

async def gaea_clicker_godhoodinfo(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodinfo")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodinfo()

async def gaea_clicker_godhoodgrowthinfo(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodgrowthinfo")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodgrowthinfo()

async def gaea_clicker_godhoodtransfer(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodtransfer")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodtransfer()

async def gaea_clicker_godhoodreward(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodreward")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodreward()

async def gaea_clicker_godhoodclaimed(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-godhoodclaimed")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_godhoodclaimed()

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

async def gaea_clicker_choicereward(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-choicereward")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_choicereward()

async def gaea_clicker_choiceclaimed(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-choiceclaimed")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_choiceclaimed()

async def gaea_clicker_snftmint(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-snftmint")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_snftmint()

async def gaea_clicker_snftinfo(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-snftinfo")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_snftinfo()

async def gaea_clicker_snftoblate(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-snftoblate")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_snftoblate()

async def gaea_clicker_anftmint(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-anftmint")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_anftmint()

async def gaea_clicker_anftinfo(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-anftinfo")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_anftinfo()

async def gaea_clicker_anftoblate(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-anftoblate")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_anftoblate()

async def gaea_clicker_milestoneburn(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-milestoneburn")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_milestoneburn()

async def gaea_clicker_milestoneclaim(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-milestoneclaim")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_milestoneclaim()

async def gaea_clicker_visionburn(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-visionburn")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_visionburn()

async def gaea_clicker_visionclaim(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-visionclaim")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_visionclaim()

async def gaea_clicker_fundspooling(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-fundspooling")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_fundspooling()

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

async def gaea_clicker_traincheckin(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-traincheckin")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_traincheckin()

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

async def gaea_clicker_deepchoice(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-deepchoice")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_deepchoice()

async def gaea_clicker_ticketchoice(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-ticketchoice")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_ticketchoice()

async def gaea_clicker_alltask(runname, id, userid, email, passwd, prikey, token, proxy):
    if platform.system().lower() == 'windows':
        os.system("title gaea-alltask")
    daily_task = GaeaDailyTask(GaeaClient(runname=runname, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
    return await daily_task.daily_clicker_alltask()
