import os
import re
import platform
import random
import argparse
import asyncio
import datetime
import schedule
import sys
import time
from loguru import logger
from questionary import Choice, select, text
from termcolor import cprint

from src.functions import (
    gaea_clicker_register, gaea_clicker_login, 
    gaea_clicker_session, gaea_clicker_bindaddress, 
    gaea_clicker_openblindbox, gaea_clicker_buytickets,
    gaea_clicker_earninfo, 
    gaea_clicker_era3info, gaea_clicker_referralreword,
    gaea_clicker_godhoodid, gaea_clicker_godhoodemotion, 
    gaea_clicker_godhoodinfo, gaea_clicker_godhoodgrowthinfo, 
    gaea_clicker_godhoodtransfer,
    gaea_clicker_godhoodreward, gaea_clicker_godhoodclaimed,
    gaea_clicker_emotionreward, gaea_clicker_emotionclaimed,
    gaea_clicker_choicereward, gaea_clicker_choiceclaimed,
    gaea_clicker_snftmint, gaea_clicker_snftinfo, gaea_clicker_snftoblate,
    gaea_clicker_anftmint, gaea_clicker_anftinfo, gaea_clicker_anftoblate,
    gaea_clicker_missionconnect, gaea_clicker_missioncomplete,
    gaea_clicker_milestoneburn, gaea_clicker_milestoneclaim,
    gaea_clicker_visionburn, gaea_clicker_visionclaim,
    gaea_clicker_fundspooling,
    gaea_clicker_checkin, gaea_clicker_signin, 
    gaea_clicker_dailycheckin, gaea_clicker_medalcheckin, 
    gaea_clicker_aitrain, gaea_clicker_traincheckin,
    gaea_clicker_deeptrain, gaea_clicker_tickettrain, 
    gaea_clicker_deepchoice, gaea_clicker_ticketchoice, 
    gaea_clicker_alltask
)
from src.gaea_client import GaeaClient
from src.task_manager import TaskManager
from utils.helpers import get_data_for_token
from utils.services import resolve_domain, get_web3_config, choose_emotion, choose_task_emotion, choose_choice, choose_task_choice, input_ticket, random_ticket, choose_ticket_level
from config import set_envsion, GAEA_API

MODULE_MAPPING = {
    'gaea_clicker_register':          gaea_clicker_register,
    'gaea_clicker_login':             gaea_clicker_login,
    'gaea_clicker_session':           gaea_clicker_session,
    'gaea_clicker_bindaddress':       gaea_clicker_bindaddress,
    'gaea_clicker_openblindbox':      gaea_clicker_openblindbox,
    'gaea_clicker_buytickets':        gaea_clicker_buytickets,
    'gaea_clicker_earninfo':          gaea_clicker_earninfo,
    'gaea_clicker_era3info':          gaea_clicker_era3info,
    'gaea_clicker_referralreword':    gaea_clicker_referralreword,
    'gaea_clicker_godhoodid':         gaea_clicker_godhoodid,
    'gaea_clicker_godhoodemotion':    gaea_clicker_godhoodemotion,
    'gaea_clicker_godhoodinfo':       gaea_clicker_godhoodinfo,
    'gaea_clicker_godhoodgrowthinfo': gaea_clicker_godhoodgrowthinfo,
    'gaea_clicker_godhoodtransfer':   gaea_clicker_godhoodtransfer,
    'gaea_clicker_godhoodreward':     gaea_clicker_godhoodreward,
    'gaea_clicker_godhoodclaimed':    gaea_clicker_godhoodclaimed,
    'gaea_clicker_emotionreward':     gaea_clicker_emotionreward,
    'gaea_clicker_emotionclaimed':    gaea_clicker_emotionclaimed,
    'gaea_clicker_choicereward':      gaea_clicker_choicereward,
    'gaea_clicker_choiceclaimed':     gaea_clicker_choiceclaimed,
    'gaea_clicker_snftmint':          gaea_clicker_snftmint,
    'gaea_clicker_snftinfo':          gaea_clicker_snftinfo,
    'gaea_clicker_snftoblate':        gaea_clicker_snftoblate,
    'gaea_clicker_anftmint':          gaea_clicker_anftmint,
    'gaea_clicker_anftinfo':          gaea_clicker_anftinfo,
    'gaea_clicker_anftoblate':        gaea_clicker_anftoblate,
    'gaea_clicker_missionconnect':    gaea_clicker_missionconnect,
    'gaea_clicker_missioncomplete':   gaea_clicker_missioncomplete,
    'gaea_clicker_milestoneburn':     gaea_clicker_milestoneburn,
    'gaea_clicker_milestoneclaim':    gaea_clicker_milestoneclaim,
    'gaea_clicker_visionburn':        gaea_clicker_visionburn,
    'gaea_clicker_visionclaim':       gaea_clicker_visionclaim,
    'gaea_clicker_fundspooling':      gaea_clicker_fundspooling,
    # 'gaea_clicker_checkin':           gaea_clicker_checkin,
    # 'gaea_clicker_signin':            gaea_clicker_signin,
    'gaea_clicker_dailycheckin':      gaea_clicker_dailycheckin,
    'gaea_clicker_medalcheckin':      gaea_clicker_medalcheckin,
    'gaea_clicker_aitrain':           gaea_clicker_aitrain,
    'gaea_clicker_traincheckin':      gaea_clicker_traincheckin,
    'gaea_clicker_deeptrain':         gaea_clicker_deeptrain,
    'gaea_clicker_tickettrain':       gaea_clicker_tickettrain,
    'gaea_clicker_deepchoice':        gaea_clicker_deepchoice,
    'gaea_clicker_ticketchoice':      gaea_clicker_ticketchoice,
    'gaea_clicker_alltask':           gaea_clicker_alltask,
}
# 预编译正则表达式
PASSWD_REGEX_PATTERN = r'^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>]).*$'
EMAIL_REGEX_PATTERN = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
# ----------------------------------------------------------------------------------------------------------

def is_id_valid(id, runeq, rungt, runlt):
    # 处理范围条件优先
    if rungt != 0 and runlt != 0: # 同时指定了大于和小于条件
        range_match = (rungt < id < runlt)
    elif rungt != 0: # 只指定了大于条件
        range_match = (id > rungt)
    elif runlt != 0: # 只指定了小于条件
        range_match = (id < runlt)
    else: # 没有指定范围条件
        range_match = True
    
    # 处理等于条件
    if isinstance(runeq, list):
        if len(runeq) == 0: # runeq 为空列表，匹配所有 ID
            equal_match = True
        else: # runeq 包含元素，只匹配列表中的 ID
            equal_match = (id in runeq)
    else: # 向后兼容，处理旧的单数值情况
        if runeq != 0:
            equal_match = (id == runeq)
        else:
            equal_match = True
    
    # 综合判断：必须同时满足范围条件和等于条件
    match = range_match and equal_match
    # logger.debug(f"is_id_valid - id: {id} runeq: {runeq} rungt: {rungt} runlt: {runlt} match: {match}")
    return match

async def limit_concurrency(semaphore, func, **kwargs):
    async with semaphore:
        return await func(**kwargs)

async def gaea_run_module_multiple_times(module, count, runname, id, email, passwd, userid, token, prikey, proxy):
    result = await module(runname, id, userid, email, passwd, prikey, token, proxy)
    logger.debug(f"id: {id} userid: {userid} email: {email} result: {result}")
    
    delay = random.randint(5, 10)
    logger.debug(f"id: {id} userid: {userid} email: {email} account delay: {delay} seconds")
    await asyncio.sleep(delay)

async def gaea_run_modules(module, runname, runeq, rungt, runlt, runthread):
    datas = get_data_for_token(runname)
    logger.info(f"runname: {runname} runeq: {runeq} rungt: {rungt} runlt: {runlt}")

    # datas随机乱序
    data_pairs = list(enumerate(datas, start=1))
    random.shuffle(data_pairs)

    if runthread<=0:
        # runthread = sum(1 for id, _ in enumerate(datas, start=1) if is_id_valid(id, runeq, rungt, runlt))
        runthread = sum(1 for id, _ in enumerate(data_pairs , start=1) if is_id_valid(id, runeq, rungt, runlt)) # datas随机乱序
        # logger.debug(f"runthread: {runthread}")
    runthread = min(runthread, 10)
    logger.info(f"runname: {runname} runthread: {runthread}")
    semaphore = asyncio.Semaphore(runthread)

    count=0
    tasks = []
    # for data_id, data in enumerate(datas, start=1):
    for data_id, data in data_pairs: # datas随机乱序
        if not is_id_valid(data_id, runeq, rungt, runlt):
            continue

        parts = data.split(',')
        if len(parts) < 6:
            logger.error(f"Invalid data: ({len(parts)}){data}")
            continue

        email, passwd, userid, token, prikey, proxy = map(str.strip, parts)
        # logger.debug(f"parts: {parts}")

        if not (re.search(EMAIL_REGEX_PATTERN, email)):  # email
            logger.error(f"Invalid email: {email}")
            continue
        elif not (re.findall(PASSWD_REGEX_PATTERN, passwd)):  # passwd
            logger.error(f"Invalid password - {passwd}")
            continue
        elif proxy == 'proxy':
            logger.error(f"Invalid proxy: {proxy}")
            continue

        count+=1
        # logger.debug(f"run task_id: {data_id} create gaea_run_modules task")
        tasks.append(asyncio.create_task(
            limit_concurrency(
                semaphore,
                gaea_run_module_multiple_times,
                module=module,
                count=count,
                runname=runname,
                id=data_id,
                email=email,
                passwd=passwd,
                userid=userid,
                token=token,
                prikey=prikey,
                proxy=proxy
            )
        ))
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.warning("Tasks were cancelled.")
    except Exception as e:
        logger.error(f"Error occurred while running tasks: {e}")

def run_module(module, runname, runeq, rungt, runlt, runthread):
    if module in [gaea_clicker_aitrain, gaea_clicker_deeptrain, gaea_clicker_tickettrain, gaea_clicker_alltask]:
        emotion = choose_emotion()
        os.environ['CHOOSE_EMOTION'] = emotion
        if module in [gaea_clicker_alltask]:
            task_emotion = choose_task_emotion()
            os.environ['TASK_EMOTION'] = task_emotion
    
    if module in [gaea_clicker_deepchoice, gaea_clicker_ticketchoice, gaea_clicker_alltask]:
        choice = choose_choice()
        os.environ['CHOOSE_CHOICE'] = choice
        if module in [gaea_clicker_alltask]:
            task_choice = choose_task_choice()
            os.environ['TASK_CHOICE'] = task_choice
    
    if module in [gaea_clicker_milestoneburn]:
        task_ticket = input_ticket()
        os.environ['TASK_TICKET'] = task_ticket
        task_ticket_random = random_ticket()
        os.environ['TASK_TICKET_RANDOM'] = task_ticket_random
    
    if module in [gaea_clicker_buytickets]:
        ticket_level = choose_ticket_level()
        os.environ['TICKET_LEVEL'] = ticket_level
    
    asyncio.run(gaea_run_modules(module=module, runname=runname, runeq=runeq, rungt=rungt, runlt=runlt, runthread=runthread))

# ---------------------------------------------------------------------------------------------------------- main one

def main1(runname, runeq, rungt, runlt, runthread):
    try:
        while True:
            if platform.system().lower() == 'windows':
                os.system("title main")
            answer = select(
                'Choose',
                choices=[
                    Choice("🚀 Gaea tasks - register",                     'gaea_clicker_register',           shortcut_key="a"),
                    Choice("🚀 Gaea tasks - login",                        'gaea_clicker_login',              shortcut_key="b"),
                    Choice("🚀 Gaea tasks - session",                      'gaea_clicker_session',            shortcut_key="c"),
                    Choice("🔥 Gaea tasks - bindaddress",                  'gaea_clicker_bindaddress',        shortcut_key="d"),
                    Choice("🔥 Gaea tasks - openblindbox",                 'gaea_clicker_openblindbox',       shortcut_key="e"),
                    Choice("🐌 Gaea tasks - buytickets",                   'gaea_clicker_buytickets',         shortcut_key="f"),
                    Choice("🔥 Gaea tasks - earninfo",                     'gaea_clicker_earninfo',           shortcut_key="g"),
                    # Choice("🔥 Gaea tasks - era3info",                     'gaea_clicker_era3info',           shortcut_key="g"), # 第三纪信息 - era3
                    # Choice("🔥 Gaea tasks - referralreword",               'gaea_clicker_referralreword',     shortcut_key="m"), # 邀请奖励
                    # Choice("🐌 Gaea tasks - godhoodid",                    'gaea_clicker_godhoodid',          shortcut_key="g"), # 购买神格卡 - inviter
                    # Choice("🔥 Gaea tasks - godhoodemotion",               'gaea_clicker_godhoodemotion',     shortcut_key="g"), # 上传神格情绪
                    # Choice("🔥 Gaea tasks - godhoodinfo",                  'gaea_clicker_godhoodinfo',        shortcut_key="g"), # 神格卡信息
                    # Choice("🔥 Gaea tasks - godhoodgrowthinfo",            'gaea_clicker_godhoodgrowthinfo',  shortcut_key="g"), # ID卡等级信息 - exp
                    Choice("🐌 Gaea tasks - godhoodtransfer",              'gaea_clicker_godhoodtransfer',    shortcut_key="h"), # USD划转
                    Choice("🔥 Gaea tasks - godhoodreward",                'gaea_clicker_godhoodreward',      shortcut_key="i"),
                    Choice("🐌 Gaea tasks - godhoodclaimed",               'gaea_clicker_godhoodclaimed',     shortcut_key="m"),
                    Choice("🔥 Gaea tasks - emotionreward",                'gaea_clicker_emotionreward',      shortcut_key="n"),
                    Choice("🐌 Gaea tasks - emotionclaimed",               'gaea_clicker_emotionclaimed',     shortcut_key="o"),
                    Choice("🔥 Gaea tasks - choicereward",                 'gaea_clicker_choicereward',       shortcut_key="p"),
                    Choice("🐌 Gaea tasks - choiceclaimed",                'gaea_clicker_choiceclaimed',      shortcut_key="q"),
                    Choice("🐌 Gaea tasks - snftmint",                     'gaea_clicker_snftmint',           shortcut_key="r"),
                    Choice("🔥 Gaea tasks - snftinfo",                     'gaea_clicker_snftinfo',           shortcut_key="s"),
                    Choice("🐌 Gaea tasks - snftoblate   (🈷️)",            'gaea_clicker_snftoblate',         shortcut_key="t"),
                    Choice("🐌 Gaea tasks - anftmint",                     'gaea_clicker_anftmint',           shortcut_key="u"),
                    Choice("🔥 Gaea tasks - anftinfo",                     'gaea_clicker_anftinfo',           shortcut_key="v"),
                    Choice("🐌 Gaea tasks - anftoblate   (🈷️)",            'gaea_clicker_anftoblate',         shortcut_key="w"),
                    # Choice("🔥 Gaea tasks - missionconnect",               'gaea_clicker_missionconnect',     shortcut_key="w"),
                    # Choice("🔥 Gaea tasks - missioncomplete",              'gaea_clicker_missioncomplete',    shortcut_key="w"),
                    Choice("🔥 Gaea tasks - milestoneburn",                'gaea_clicker_milestoneburn',      shortcut_key="x"),
                    Choice("🐌 Gaea tasks - milestoneclaim",               'gaea_clicker_milestoneclaim',     shortcut_key="y"),
                    # Choice("🔥 Gaea tasks - visionburn",                   'gaea_clicker_visionburn',         shortcut_key="x"),
                    # Choice("🐌 Gaea tasks - visionclaim",                  'gaea_clicker_visionclaim',        shortcut_key="y"),
                    Choice("🐌 Fund tasks - fundspooling",                 'gaea_clicker_fundspooling',       shortcut_key="z"),
                    # Choice("🔥 Gaea daily tasks - checkin        (☀️)",    'gaea_clicker_checkin',            shortcut_key="1"),
                    # Choice("🔥 Gaea daily tasks - signin         (☀️)",    'gaea_clicker_signin',             shortcut_key="2"),
                    Choice("🔥 Gaea daily tasks - dailycheckin   (☀️)",    'gaea_clicker_dailycheckin',       shortcut_key="1"),
                    Choice("🔥 Gaea daily tasks - medalcheckin   (☀️)",    'gaea_clicker_medalcheckin',       shortcut_key="2"),
                    Choice("🔥 Gaea daily tasks - aitrain        (☀️)",    'gaea_clicker_aitrain',            shortcut_key="3"),
                    Choice("🔥 Gaea daily tasks - traincheckin   (☀️)",    'gaea_clicker_traincheckin',       shortcut_key="4"),
                    Choice("🔥 Gaea daily tasks - deeptrain      (☀️)",    'gaea_clicker_deeptrain',          shortcut_key="5"),
                    Choice("🔥 Gaea daily tasks - tickettrain    (☀️)",    'gaea_clicker_tickettrain',        shortcut_key="6"),
                    Choice("🔥 Gaea daily tasks - deepchoice     (☀️)",    'gaea_clicker_deepchoice',         shortcut_key="7"),
                    Choice("🔥 Gaea daily tasks - ticketchoice   (☀️)",    'gaea_clicker_ticketchoice',       shortcut_key="8"),
                    Choice("🔥 Gaea daily tasks - alltask        (☀️)",    'gaea_clicker_alltask',            shortcut_key="9"),
                    Choice('❌ Exit', "exit", shortcut_key="0")
                ],
                use_shortcuts=True,
                use_arrow_keys=True,
            ).ask()

            if answer in MODULE_MAPPING:
                run_module(MODULE_MAPPING[answer], runname, runeq, rungt, runlt, runthread)
            elif answer == 'exit':
                sys.exit()
    except (KeyboardInterrupt, asyncio.CancelledError, SystemExit) as e:
        cprint(f"\nShutting down due to: {type(e).__name__}", color='light_yellow')
        sys.exit()

# ---------------------------------------------------------------------------------------------------------- main two

def main(runname, runeq, rungt, runlt, runthread):
    try:
        while True:
            if platform.system().lower() == 'windows':
                os.system("title main")
            answer = select(
                'Choose Category',
                choices=[
                    Choice("🚀 Basic Tasks",         'basic_tasks',    shortcut_key="1"),
                    Choice("🚀 GodHood Tasks",       'godhood_tasks',  shortcut_key="2"),
                    Choice("🚀 NFTs Tasks",          'nfts_tasks',     shortcut_key="3"),
                    Choice("🔥 Daily Tasks",         'daily_tasks',    shortcut_key="4"),
                    Choice("🐌 Advanced Tasks",      'advanced_tasks', shortcut_key="5"),
                    Choice("🐌 Funds Tasks",         'funds_tasks',    shortcut_key="6"),
                    Choice('❌ Exit', "exit", shortcut_key="0")
                ],
                use_shortcuts=True,
                use_arrow_keys=True,
            ).ask()

            if answer == 'basic_tasks':
                handle_basic_tasks(runname, runeq, rungt, runlt, runthread)
            elif answer == 'godhood_tasks':
                handle_godhood_tasks(runname, runeq, rungt, runlt, runthread)
            elif answer == 'nfts_tasks':
                handle_nfts_tasks(runname, runeq, rungt, runlt, runthread)
            elif answer == 'daily_tasks':
                handle_daily_tasks(runname, runeq, rungt, runlt, runthread)
            elif answer == 'advanced_tasks':
                handle_advanced_tasks(runname, runeq, rungt, runlt, runthread)
            elif answer == 'funds_tasks':
                handle_funds_tasks(runname, runeq, rungt, runlt, runthread)
            elif answer == 'exit':
                sys.exit()
    except (KeyboardInterrupt, asyncio.CancelledError, SystemExit) as e:
        cprint(f"\nShutting down due to: {type(e).__name__}", color='light_yellow')
        sys.exit()

def handle_basic_tasks(runname, runeq, rungt, runlt, runthread):
    answer = select(
        'Basic Tasks',
        choices=[
            Choice("🚀 Basic tasks - register",                     'gaea_clicker_register',           shortcut_key="1"),
            Choice("🚀 Basic tasks - login",                        'gaea_clicker_login',              shortcut_key="2"),
            Choice("🚀 Basic tasks - session",                      'gaea_clicker_session',            shortcut_key="3"),
            Choice("🔥 Basic tasks - bindaddress",                  'gaea_clicker_bindaddress',        shortcut_key="4"),
            Choice("🔥 Basic tasks - openblindbox",                 'gaea_clicker_openblindbox',       shortcut_key="5"),
            Choice("🐌 Basic tasks - buytickets",                   'gaea_clicker_buytickets',         shortcut_key="6"),
            Choice("🔥 Basic tasks - earninfo",                     'gaea_clicker_earninfo',           shortcut_key="7"),
            Choice("🔥 Basic tasks - era3info",                     'gaea_clicker_era3info',           shortcut_key="8"), # 第三纪信息 - era3
            Choice("🔥 Basic tasks - referralreword",               'gaea_clicker_referralreword',     shortcut_key="9"), # 邀请奖励
            Choice("⬅ Back", "back", shortcut_key="0")
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()

    if answer in MODULE_MAPPING:
        run_module(MODULE_MAPPING[answer], runname, runeq, rungt, runlt, runthread)
    elif answer == 'back':
        return

def handle_godhood_tasks(runname, runeq, rungt, runlt, runthread):
    answer = select(
        'GodHood Tasks',
        choices=[
            Choice("🐌 GodHood tasks - godhoodid",                    'gaea_clicker_godhoodid',          shortcut_key="1"), # 购买神格卡 - inviter
            Choice("🔥 GodHood tasks - godhoodemotion",               'gaea_clicker_godhoodemotion',     shortcut_key="2"), # 上传神格情绪
            Choice("🔥 GodHood tasks - godhoodinfo",                  'gaea_clicker_godhoodinfo',        shortcut_key="3"), # 神格卡信息
            Choice("🔥 GodHood tasks - godhoodgrowthinfo",            'gaea_clicker_godhoodgrowthinfo',  shortcut_key="4"), # ID卡等级信息 - exp
            Choice("🐌 GodHood tasks - godhoodtransfer",              'gaea_clicker_godhoodtransfer',    shortcut_key="5"), # USD划转
            Choice("🔥 GodHood tasks - godhoodreward",                'gaea_clicker_godhoodreward',      shortcut_key="6"),
            Choice("🐌 GodHood tasks - godhoodclaimed",               'gaea_clicker_godhoodclaimed',     shortcut_key="7"),
            Choice("⬅ Back", "back", shortcut_key="0")
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()

    if answer in MODULE_MAPPING:
        run_module(MODULE_MAPPING[answer], runname, runeq, rungt, runlt, runthread)
    elif answer == 'back':
        return

def handle_nfts_tasks(runname, runeq, rungt, runlt, runthread):
    answer = select(
        'NFTs Tasks',
        choices=[
            Choice("🐌 NFTs tasks - snftmint",                     'gaea_clicker_snftmint',           shortcut_key="1"),
            Choice("🔥 NFTs tasks - snftinfo",                     'gaea_clicker_snftinfo',           shortcut_key="2"),
            Choice("🐌 NFTs tasks - snftoblate   (🈷️)",            'gaea_clicker_snftoblate',         shortcut_key="3"),
            Choice("🐌 NFTs tasks - anftmint",                     'gaea_clicker_anftmint',           shortcut_key="4"),
            Choice("🔥 NFTs tasks - anftinfo",                     'gaea_clicker_anftinfo',           shortcut_key="5"),
            Choice("🐌 NFTs tasks - anftoblate   (🈷️)",            'gaea_clicker_anftoblate',         shortcut_key="6"),
            Choice("⬅ Back", "back", shortcut_key="0")
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()

    if answer in MODULE_MAPPING:
        run_module(MODULE_MAPPING[answer], runname, runeq, rungt, runlt, runthread)
    elif answer == 'back':
        return

def handle_daily_tasks(runname, runeq, rungt, runlt, runthread):
    answer = select(
        'Daily Tasks',
        choices=[
            # Choice("🔥 Daily tasks - checkin        (☀️)",    'gaea_clicker_checkin',            shortcut_key="1"),
            # Choice("🔥 Daily tasks - signin         (☀️)",    'gaea_clicker_signin',             shortcut_key="2"),
            Choice("🔥 Daily tasks - dailycheckin   (☀️)",    'gaea_clicker_dailycheckin',       shortcut_key="1"),
            Choice("🔥 Daily tasks - medalcheckin   (☀️)",    'gaea_clicker_medalcheckin',       shortcut_key="2"),
            Choice("🔥 Daily tasks - aitrain        (☀️)",    'gaea_clicker_aitrain',            shortcut_key="3"),
            Choice("🔥 Daily tasks - deeptrain      (☀️)",    'gaea_clicker_deeptrain',          shortcut_key="4"),
            Choice("🔥 Daily tasks - tickettrain    (☀️)",    'gaea_clicker_tickettrain',        shortcut_key="5"),
            Choice("🔥 Daily tasks - traincheckin   (☀️)",    'gaea_clicker_traincheckin',       shortcut_key="6"),
            Choice("🔥 Daily tasks - deepchoice     (☀️)",    'gaea_clicker_deepchoice',         shortcut_key="7"),
            Choice("🔥 Daily tasks - ticketchoice   (☀️)",    'gaea_clicker_ticketchoice',       shortcut_key="8"),
            Choice("🔥 Daily tasks - alltask        (☀️)",    'gaea_clicker_alltask',            shortcut_key="9"),
            Choice("⬅ Back", "back", shortcut_key="0")
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()

    if answer in MODULE_MAPPING:
        run_module(MODULE_MAPPING[answer], runname, runeq, rungt, runlt, runthread)
    elif answer == 'back':
        return

def handle_advanced_tasks(runname, runeq, rungt, runlt, runthread):
    answer = select(
        'Advanced Tasks',
        choices=[
            Choice("🔥 Advanced tasks - missionconnect",               'gaea_clicker_missionconnect',     shortcut_key="1"),
            Choice("🔥 Advanced tasks - missioncomplete",              'gaea_clicker_missioncomplete',    shortcut_key="2"),
            Choice("🔥 Advanced tasks - milestoneburn",                'gaea_clicker_milestoneburn',      shortcut_key="3"),
            Choice("🐌 Advanced tasks - milestoneclaim",               'gaea_clicker_milestoneclaim',     shortcut_key="4"),
            Choice("🔥 Advanced tasks - visionburn",                   'gaea_clicker_visionburn',         shortcut_key="5"),
            Choice("🐌 Advanced tasks - visionclaim",                  'gaea_clicker_visionclaim',        shortcut_key="6"),
            Choice("⬅ Back", "back", shortcut_key="0")
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()

    if answer in MODULE_MAPPING:
        run_module(MODULE_MAPPING[answer], runname, runeq, rungt, runlt, runthread)
    elif answer == 'back':
        return

def handle_funds_tasks(runname, runeq, rungt, runlt, runthread):
    answer = select(
        'Funds Tasks',
        choices=[
            Choice("🔥 Funds tasks - emotionreward",                'gaea_clicker_emotionreward',      shortcut_key="1"),
            Choice("🐌 Funds tasks - emotionclaimed",               'gaea_clicker_emotionclaimed',     shortcut_key="2"),
            Choice("🔥 Funds tasks - choicereward",                 'gaea_clicker_choicereward',       shortcut_key="3"),
            Choice("🐌 Funds tasks - choiceclaimed",                'gaea_clicker_choiceclaimed',      shortcut_key="4"),
            Choice("🐌 Funds tasks - fundspooling",                 'gaea_clicker_fundspooling',       shortcut_key="5"),
            Choice("⬅ Back", "back", shortcut_key="0")
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()

    if answer in MODULE_MAPPING:
        run_module(MODULE_MAPPING[answer], runname, runeq, rungt, runlt, runthread)
    elif answer == 'back':
        return

# ---------------------------------------------------------------------------------------------------------- auto

async def gaea_daily_task_modules(module, runname, runeq, runthread):
    module_mapping = {
        gaea_clicker_register:      "launch_clicker_register",
        gaea_clicker_login:         "launch_clicker_login",
        gaea_clicker_dailycheckin:  "launch_clicker_dailycheckin",
        gaea_clicker_medalcheckin:  "launch_clicker_medalcheckin",
        gaea_clicker_aitrain:       "launch_clicker_aitrain",
        gaea_clicker_deeptrain:     "launch_clicker_deeptrain",
        gaea_clicker_tickettrain:   "launch_clicker_tickettrain",
        gaea_clicker_deepchoice:    "launch_clicker_deepchoice",
        gaea_clicker_ticketchoice:  "launch_clicker_ticketchoice",
        gaea_clicker_traincheckin:  "launch_clicker_traincheckin",
        gaea_clicker_alltask:       "launch_clicker_alltask",
    }
    module_name = module_mapping.get(module, "none")

    if runthread==0:
        datas = get_data_for_token(runname)
        runthread=len(datas)
    if int(runeq)>0:
        runthread=1

    tasks = []
    task_manager = TaskManager(runname)
    for thread in range(1, runthread+1):
        delay = random.randint(10, 20)
        logger.debug(f"func: {module_name} thread: {thread} delay: {delay} seconds")
        await asyncio.sleep(delay)

        # logger.info(f"func: {module_name} thread: {thread} runeq: {runeq} module: {module_name}")
        task_func = getattr(task_manager, module_name, None)
        tasks.append(asyncio.create_task(
            task_func(thread, runeq, module_name)
        ))

    await asyncio.gather(*tasks)

def daily_task_module():
    logger.info("Execute alltask scheduled task...")
    asyncio.run(gaea_daily_task_modules(module=gaea_clicker_alltask, runname=run_name, runeq=run_eq, runthread=run_thread))

def main_task(run_hour: int):
    # 获取当前时间
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"current_time: {current_time}")
    # # 设置定时任务
    # task_time = f"{str(run_run).zfill(2)}:{str(random.randint(0, 59)).zfill(2)}"
    # logger.info(f"The scheduled task will start at {task_time} every day ...")
    # schedule.every().day.at(task_time).do(daily_task_module)
    # 设置定时任务
    if run_hour==0:
        run_hour = datetime.datetime.now().hour
        run_minute = datetime.datetime.now().minute
        task_time = f"{str(run_hour).zfill(2)}:{str(random.randint(run_minute, 59)).zfill(2)}"
    else:
        task_time = f"{str(run_hour).zfill(2)}:{str(random.randint(0, 59)).zfill(2)}"
    logger.info(f"The scheduled task will start at {task_time} every day ...")
    schedule.every().day.at(task_time).do(daily_task_module)

# ----------------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    # 初始化参数
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--auto', type=bool, default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument('-r', '--run', type=int, default=0)
    parser.add_argument('-d', '--debug', type=bool, default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument('-n', '--name', type=str, default='')
    parser.add_argument('-e', '--equal', nargs='+', type=int, default=[])
    parser.add_argument('-g', '--greater', type=int, default=0)
    parser.add_argument('-l', '--less', type=int, default=0)
    parser.add_argument('-t', '--thread', type=int, default=0)
    args = parser.parse_args()
    run_auto = bool(args.auto)
    run_run = int(args.run)
    run_debug = bool(args.debug)
    run_name = str(args.name)
    run_eq = list(args.equal)
    run_gt = int(args.greater)
    run_lt = int(args.less)
    run_thread = int(args.thread)

    # 日志级别
    log_level = "DEBUG" if run_debug else "INFO"
    logger.remove()
    logger.add(sys.stdout, level=log_level)
    # logger.add("data/logs/logging.log", rotation="100 MB", level=log_level)

    # 解析域名
    ip_addresses = asyncio.run(resolve_domain(GAEA_API))
    logger.debug(f"resolve_domain {GAEA_API} => ip: {ip_addresses}")
    # 获取远程配置
    asyncio.run(get_web3_config())

    if run_auto:
        emotion = choose_emotion()
        os.environ['CHOOSE_EMOTION'] = emotion
        task_emotion = choose_task_emotion()
        os.environ['TASK_EMOTION'] = task_emotion

        choice = choose_choice()
        os.environ['CHOOSE_CHOICE'] = choice
        task_choice = choose_task_choice()
        os.environ['TASK_CHOICE'] = task_choice

        if 0 <= run_run <= 23:
            main_task(run_run)
        else:
            logger.error(f"Invalid parameter, run: {run_run} must be between 0 and 23.")
            sys.exit(1)

        # 无限循环，以便定时任务能够持续运行
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        logger.info("Start now ...")
        main(run_name, run_eq, run_gt, run_lt, run_thread)
        logger.info("All wallets completed their tasks!")
