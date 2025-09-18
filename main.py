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
from questionary import Choice, select
from termcolor import cprint

from src.functions import (
    gaea_clicker_register, gaea_clicker_login, 
    gaea_clicker_session, gaea_clicker_bindaddress, 
    gaea_clicker_godhoodinfo, gaea_clicker_godhoodid, gaea_clicker_godhoodemotion, 
    gaea_clicker_era3info, gaea_clicker_earninfo, 
    gaea_clicker_referralreword, gaea_clicker_openblindbox, 
    gaea_clicker_invitereward, gaea_clicker_inviteclaimed,
    gaea_clicker_emotionreward, gaea_clicker_emotionclaimed,
    gaea_clicker_choicereward, gaea_clicker_choiceclaimed,
    gaea_clicker_mintnft, gaea_clicker_nftinfo, gaea_clicker_nftoblate,
    gaea_clicker_checkin, gaea_clicker_signin,
    gaea_clicker_dailycheckin, gaea_clicker_medalcheckin, 
    gaea_clicker_aitrain, gaea_clicker_aicheckin,
    gaea_clicker_deeptrain, gaea_clicker_deeptrain_ticket, 
    gaea_clicker_deepchoice, gaea_clicker_deepchoice_ticket, 
    gaea_clicker_alltask
)
from src.gaea_client import GaeaClient
from src.task_manager import TaskManager
from utils.helpers import get_data_for_token
from utils.services import resolve_domain, get_web3_config
from config import set_envsion, GAEA_API

MODULE_MAPPING = {
    'gaea_clicker_register':     gaea_clicker_register,
    'gaea_clicker_login':        gaea_clicker_login,
    'gaea_clicker_session':      gaea_clicker_session,
    'gaea_clicker_bindaddress':    gaea_clicker_bindaddress,
    'gaea_clicker_godhoodinfo':    gaea_clicker_godhoodinfo,
    'gaea_clicker_godhoodid':      gaea_clicker_godhoodid,
    'gaea_clicker_godhoodemotion': gaea_clicker_godhoodemotion,
    'gaea_clicker_era3info':       gaea_clicker_era3info,
    'gaea_clicker_earninfo':       gaea_clicker_earninfo,
    'gaea_clicker_referralreword': gaea_clicker_referralreword,
    'gaea_clicker_openblindbox':   gaea_clicker_openblindbox,
    'gaea_clicker_invitereward':   gaea_clicker_invitereward,
    'gaea_clicker_inviteclaimed':  gaea_clicker_inviteclaimed,
    'gaea_clicker_emotionreward':  gaea_clicker_emotionreward,
    'gaea_clicker_emotionclaimed': gaea_clicker_emotionclaimed,
    'gaea_clicker_choicereward':   gaea_clicker_choicereward,
    'gaea_clicker_choiceclaimed':  gaea_clicker_choiceclaimed,
    'gaea_clicker_mintnft':        gaea_clicker_mintnft,
    'gaea_clicker_nftinfo':        gaea_clicker_nftinfo,
    'gaea_clicker_nftoblate':      gaea_clicker_nftoblate,
    # 'gaea_clicker_upgradenft':     gaea_clicker_upgradenft,
    # 'gaea_clicker_checkin':    gaea_clicker_checkin,
    # 'gaea_clicker_signin':     gaea_clicker_signin,
    'gaea_clicker_dailycheckin': gaea_clicker_dailycheckin,
    'gaea_clicker_medalcheckin': gaea_clicker_medalcheckin,
    'gaea_clicker_aitrain':      gaea_clicker_aitrain,
    'gaea_clicker_deeptrain':    gaea_clicker_deeptrain,
    'gaea_clicker_deeptrain_ticket':  gaea_clicker_deeptrain_ticket,
    'gaea_clicker_deepchoice':    gaea_clicker_deepchoice,
    'gaea_clicker_deepchoice_ticket':  gaea_clicker_deepchoice_ticket,
    'gaea_clicker_aicheckin':    gaea_clicker_aicheckin,
    'gaea_clicker_alltask':      gaea_clicker_alltask,
}
# 预编译正则表达式
PASSWD_REGEX_PATTERN = r'^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>]).*$'
EMAIL_REGEX_PATTERN = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
# ----------------------------------------------------------------------------------------------------------

def is_id_valid(id, runeq, rungt, runlt):
    match = False
    if runeq != 0:
        match |= (id == runeq)
    if rungt != 0 and runlt != 0:
        match |= (rungt < id < runlt)
    elif rungt != 0:
        match |= (id > rungt)
    elif runlt != 0:
        match |= (id < runlt)
    elif runeq == 0 and rungt == 0 and runlt == 0:
        match |= True
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

    if runthread<=0:
        runthread = sum(1 for id, _ in enumerate(datas, start=1) if is_id_valid(id, runeq, rungt, runlt))
        # logger.debug(f"runthread: {runthread}")
    runthread = min(runthread, 10)
    logger.info(f"runname: {runname} runthread: {runthread}")
    semaphore = asyncio.Semaphore(runthread)

    count=0
    tasks = []
    for data_id, data in enumerate(datas, start=1):
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
        logger.debug(f"run task_id: {data_id} create gaea_run_modules task")
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
    if module in [gaea_clicker_aitrain, gaea_clicker_deeptrain, gaea_clicker_deeptrain_ticket, gaea_clicker_alltask]:
        emotion = choose_emotion()
        os.environ['CHOOSE_EMOTION'] = emotion
        if module in [gaea_clicker_alltask]:
            task_emotion = choose_task_emotion()
            os.environ['TASK_EMOTION'] = task_emotion
    
    if module in [gaea_clicker_deepchoice, gaea_clicker_deepchoice_ticket, gaea_clicker_alltask]:
        choice = choose_choice()
        os.environ['CHOOSE_CHOICE'] = choice
        if module in [gaea_clicker_alltask]:
            task_choice = choose_task_choice()
            os.environ['TASK_CHOICE'] = task_choice
    asyncio.run(gaea_run_modules(module=module, runname=runname, runeq=runeq, rungt=rungt, runlt=runlt, runthread=runthread))

def main(runname, runeq, rungt, runlt, runthread):
    try:
        while True:
            if platform.system().lower() == 'windows':
                os.system("title main")
            answer = select(
                'Choose',
                choices=[
                    Choice("🚀 Gaea tasks - register",        'gaea_clicker_register',        shortcut_key="a"),
                    Choice("🚀 Gaea tasks - login",           'gaea_clicker_login',           shortcut_key="b"),
                    Choice("🚀 Gaea tasks - session",         'gaea_clicker_session',         shortcut_key="c"),
                    Choice("🔥 Gaea tasks - bindaddress",     'gaea_clicker_bindaddress',     shortcut_key="d"),
                    Choice("🚀 Gaea tasks - godhoodinfo",     'gaea_clicker_godhoodinfo',     shortcut_key="e"),
                    Choice("🔥 Gaea tasks - godhoodid",       'gaea_clicker_godhoodid',       shortcut_key="f"),
                    Choice("🔥 Gaea tasks - godhoodemotion",  'gaea_clicker_godhoodemotion',  shortcut_key="g"),
                    Choice("🚀 Gaea tasks - era3info",        'gaea_clicker_era3info',        shortcut_key="h"),
                    Choice("🚀 Gaea tasks - earninfo",        'gaea_clicker_earninfo',        shortcut_key="i"),
                    Choice("🔥 Gaea tasks - referralreword",  'gaea_clicker_referralreword',  shortcut_key="l"),
                    Choice("🔥 Gaea tasks - openblindbox",    'gaea_clicker_openblindbox',    shortcut_key="m"),
                    Choice("🔥 Gaea tasks - invitereward",    'gaea_clicker_invitereward',    shortcut_key="n"),
                    Choice("🔥 Gaea tasks - inviteclaimed",   'gaea_clicker_inviteclaimed',   shortcut_key="o"),
                    Choice("🔥 Gaea tasks - emotionreward",   'gaea_clicker_emotionreward',   shortcut_key="p"),
                    Choice("🔥 Gaea tasks - emotionclaimed",  'gaea_clicker_emotionclaimed',  shortcut_key="q"),
                    Choice("🔥 Gaea tasks - choicereward",    'gaea_clicker_choicereward',    shortcut_key="r"),
                    Choice("🔥 Gaea tasks - choiceclaimed",   'gaea_clicker_choiceclaimed',   shortcut_key="s"),
                    Choice("🔥 Gaea tasks - mintNFT",         'gaea_clicker_mintnft',         shortcut_key="t"),
                    Choice("🔥 Gaea tasks - nftinfo",         'gaea_clicker_nftinfo',         shortcut_key="u"),
                    Choice("🔥 Gaea tasks - nftoblate",       'gaea_clicker_nftoblate',       shortcut_key="v"),
                    # Choice("🔥 Gaea tasks - upgradeNFT",      'gaea_clicker_upgradenft',      shortcut_key="v"),
                    # Choice("🔥 Gaea daily tasks - checkin   (Once a day)",   'gaea_clicker_checkin',   shortcut_key="1"),
                    # Choice("🔥 Gaea daily tasks - signin    (Once a day)",   'gaea_clicker_signin',    shortcut_key="2"),
                    Choice("🔥 Gaea daily tasks - dailycheckin   (Once a day)",   'gaea_clicker_dailycheckin',   shortcut_key="1"),
                    Choice("🔥 Gaea daily tasks - medalcheckin   (Once a day)",   'gaea_clicker_medalcheckin',   shortcut_key="2"),
                    Choice("🔥 Gaea daily tasks - aitrain        (Once a day)",   'gaea_clicker_aitrain',     shortcut_key="3"),
                    Choice("🚀 Gaea daily tasks - deeptrain      (Once a Phase)", 'gaea_clicker_deeptrain',   shortcut_key="4"),
                    Choice("🚀 Gaea daily tasks - tickettrain    (Once a Phase)", 'gaea_clicker_deeptrain_ticket', shortcut_key="5"),
                    Choice("🔥 Gaea daily tasks - aicheckin      (Once a day)",   'gaea_clicker_aicheckin',   shortcut_key="6"),
                    Choice("🚀 Gaea daily tasks - deepchoice     (Once a Phase)", 'gaea_clicker_deepchoice',   shortcut_key="7"),
                    Choice("🚀 Gaea daily tasks - ticketchoice   (Once a Phase)", 'gaea_clicker_deepchoice_ticket', shortcut_key="8"),
                    Choice("🔥 Gaea daily tasks - alltask        (Once a day)",   'gaea_clicker_alltask',     shortcut_key="9"),
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

# ----------------------------------------------------------------------------------------------------------

def choose_emotion():
    emotion_int = select(
        'Choose Emotion',
        choices=[
            Choice("Random",   '0', shortcut_key="0"),
            Choice("Postive",  '1', shortcut_key="1"),
            Choice("Neutral",  '2', shortcut_key="2"),
            Choice("Negative", '3', shortcut_key="3"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    return emotion_int

def choose_task_emotion():
    task_choice = select(
        'Choose Task',
        choices=[
            Choice("No Train",     '0', shortcut_key="0"),
            Choice("DeepTrain",    '1', shortcut_key="1"),
            Choice("TicketTrain",  '2', shortcut_key="2"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    return task_choice

def choose_choice():
    choice_int = select(
        'Choose Choice',
        choices=[
            Choice("Random",      '0', shortcut_key="0"),
            Choice("Safeguarding",'1', shortcut_key="1"),
            Choice("Balancing",   '2', shortcut_key="2"),
            Choice("Advancing",   '3', shortcut_key="3"),
            Choice("Leaping",     '4', shortcut_key="4"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    return choice_int

def choose_task_choice():
    task_choice = select(
        'Choose Task',
        choices=[
            Choice("No Choice",    '0', shortcut_key="0"),
            Choice("DeepChoice",   '1', shortcut_key="1"),
            Choice("TicketChoice", '2', shortcut_key="2"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    return task_choice

# ----------------------------------------------------------------------------------------------------------

async def gaea_daily_task_modules(module, runname, runeq, runthread):
    module_mapping = {
        gaea_clicker_register:     "launch_clicker_register",
        gaea_clicker_login:        "launch_clicker_login",
        gaea_clicker_dailycheckin: "launch_clicker_dailycheckin",
        gaea_clicker_medalcheckin: "launch_clicker_medalcheckin",
        gaea_clicker_aitrain:      "launch_clicker_aitrain",
        gaea_clicker_deeptrain:    "launch_clicker_deeptrain",
        gaea_clicker_deeptrain_ticket:  "launch_clicker_deeptrain_ticket",
        gaea_clicker_deepchoice:    "launch_clicker_deepchoice",
        gaea_clicker_deepchoice_ticket:  "launch_clicker_deepchoice_ticket",
        gaea_clicker_aicheckin:    "launch_clicker_aicheckin",
        gaea_clicker_alltask:      "launch_clicker_alltask",
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
    parser.add_argument('-e', '--equal', type=int, default=0)
    parser.add_argument('-g', '--greater', type=int, default=0)
    parser.add_argument('-l', '--less', type=int, default=0)
    parser.add_argument('-t', '--thread', type=int, default=0)
    args = parser.parse_args()
    run_auto = bool(args.auto)
    run_run = int(args.run)
    run_debug = bool(args.debug)
    run_name = str(args.name)
    run_eq = int(args.equal)
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
