import os
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

from src.functions import gaea_clicker_checkin, gaea_clicker_signin, gaea_clicker_aitrain, gaea_clicker_aicheckin, gaea_clicker_alltask, gaea_clicker_deeptrain
from src.gaea_client import GaeaClient
from src.task_manager import TaskManager
from utils.helpers import get_data_for_token
from config import set_envsion

async def gaea_run(module, id, userid, email, passwd, prikey, token, proxy, client: GaeaClient = None):
    logger.debug(f"id: {id} userid: {userid} email: {email} RUN")
    return await module(id, userid, email, passwd, prikey, token, proxy)

async def gaea_run_module_multiple_times(module, delaycount, id, userid, email, passwd, prikey, token, proxy):
    delay = random.randint(1, delaycount)
    logger.info(f"id: {id} userid: {userid} email: {email} account delay: {delay} seconds")
    await asyncio.sleep(delay)

    while True:
        result = await gaea_run(module, id, userid, email, passwd, prikey, token, proxy)
        logger.debug(f"id: {id} userid: {userid} email: {email} result: {result}")
        # No loop ends
        break

async def gaea_run_modules(module, runname, runid, runthread):
    tasks = []
    datas = get_data_for_token(runname)

    delay_count=len(datas)*5
    if int(runid) > 0:
        delay_count=5
    else:
        delay_count+=5

    id=0
    for data in datas:
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

        id+=1
        if int(runid)>0 and id!=int(runid):
            continue
        logger.debug(f"run task id: {id}")

        logger.debug(f"id: {id} create gaea_run_modules task")
        task = asyncio.create_task(gaea_run_module_multiple_times(module=module, delaycount=delay_count, id=id, userid=userid, email=email, passwd=passwd, prikey=prikey, token=token, proxy=proxy))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def gaea_run_thread_modules(module, runname, runid, runthread):
    if module == gaea_clicker_alltask:
        module_name = "launch_clicker_alltask"
    else:
        module_name = "none"

    if runthread==0:
        datas = get_data_for_token(runname)
        runthread=len(datas)
    if int(runid)>0:
        runthread=1

    tasks = []
    task_manager = TaskManager(runname)
    for thread in range(1, runthread+1):
        delay = random.randint(10, 20)
        logger.debug(f"func: {module_name} thread: {thread} delay: {delay} seconds")
        await asyncio.sleep(delay)

        task_func = getattr(task_manager, module_name)
        # logger.info(f"func: {module_name} thread: {thread} runid: {runid} module: {module_name}")
        tasks.append(asyncio.create_task(task_func(thread, runid, module_name)))

    await asyncio.gather(*tasks)

def choose_emotion():
    emotion_choice = select(
        'Choose Emotion',
        choices=[
            Choice("Postive",  '1', shortcut_key="1"),
            Choice("Neutral",  '2', shortcut_key="2"),
            Choice("Negative", '3', shortcut_key="3"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    os.environ['CHOOSE_EMOTION']=emotion_choice

def main(runname, runid, runthread):
    try:
        while True:
            if platform.system().lower() == 'windows':
                os.system("title main")
            answer = select(
                'Choose',
                choices=[
                    Choice("🔥 Gaea daily tasks - checkin   (Once a day)",  'gaea_clicker_checkin',   shortcut_key="1"),
                    Choice("🔥 Gaea daily tasks - signin    (Once a day)",  'gaea_clicker_signin',    shortcut_key="2"),
                    Choice("🔥 Gaea daily tasks - aitrain   (Once a day)",  'gaea_clicker_aitrain',   shortcut_key="3"),
                    Choice("🔥 Gaea daily tasks - aicheckin (Once a day)",  'gaea_clicker_aicheckin', shortcut_key="4"),
                    Choice("🔥 Gaea daily tasks - alltask   (Once a day)",  'gaea_clicker_alltask',   shortcut_key="5"),
                    Choice("🚀 Gaea daily tasks - deeptrain",               'gaea_clicker_deeptrain', shortcut_key="6"),
                    Choice("🚀 Gaea tasks - getpoints", 'gaea_clicker_getpoints', shortcut_key="8"),
                    Choice("🚀 Gaea tasks - getsoul",   'gaea_clicker_getsoul',   shortcut_key="9"),
                    Choice('❌ Exit', "exit", shortcut_key="0")
                ],
                use_shortcuts=True,
                use_arrow_keys=True,
            ).ask()

            if answer == 'gaea_clicker_checkin':
                asyncio.run(gaea_run_modules(module=gaea_clicker_checkin, runname=runname, runid=runid, runthread=runthread))
            elif answer == 'gaea_clicker_signin':
                asyncio.run(gaea_run_modules(module=gaea_clicker_signin, runname=runname, runid=runid, runthread=runthread))
            elif answer == 'gaea_clicker_aitrain':
                choose_emotion()
                asyncio.run(gaea_run_modules(module=gaea_clicker_aitrain, runname=runname, runid=runid, runthread=runthread))
            elif answer == 'gaea_clicker_aicheckin':
                asyncio.run(gaea_run_modules(module=gaea_clicker_aicheckin, runname=runname, runid=runid, runthread=runthread))
            elif answer == 'gaea_clicker_alltask':
                choose_emotion()
                asyncio.run(gaea_run_modules(module=gaea_clicker_alltask, runname=runname, runid=runid, runthread=runthread))
            elif answer == 'gaea_clicker_deeptrain':
                choose_emotion()
                asyncio.run(gaea_run_modules(module=gaea_clicker_deeptrain, runname=runname, runid=runid, runthread=runthread))
            elif answer == 'exit':
                sys.exit()
    except KeyboardInterrupt:
        cprint(f'\n Please press <Ctrl + C> to exit', color='light_yellow')
        sys.exit()

def job():
    logger.info("Execute alltask scheduled task...")
    asyncio.run(gaea_run_thread_modules(module=gaea_clicker_alltask, runname=run_name, runid=run_id, runthread=run_thread))

if __name__ == '__main__':
    # 初始化参数
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--auto', type=bool, default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument('-d', '--debug', type=bool, default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument('-n', '--name', type=str, default='')
    parser.add_argument('-i', '--id', type=int, default=0)
    parser.add_argument('-r', '--run', type=int, default=10)
    parser.add_argument('-t', '--thread', type=int, default=0)
    args = parser.parse_args()
    run_auto = bool(args.auto)
    run_debug = bool(args.debug)
    run_name = str(args.name)
    run_id = int(args.id)
    run_run = int(args.run)
    run_thread = int(args.thread)

    # 日志级别
    log_level="INFO"
    if run_debug:
        log_level="DEBUG"
    logger.remove()
    logger.add(sys.stdout, level=log_level)
    # logger.add("data/logs/logging.log", rotation="100 MB", level=log_level)

    if run_auto:
        choose_emotion()
        if 0 <= run_run <= 23:
            task_time=str(run_run).zfill(2)+":30"
            logger.info(f"The scheduled task will start at {task_time} every day ...")
            schedule.every().day.at(task_time).do(job)
        else:
            logger.error(f"Invalid parameter, run: {run_run} must be between 0 and 23.")
            sys.exit(1)

        # 无限循环，以便定时任务能够持续运行
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        logger.info("Start now ...")
        main(run_name, run_id, run_thread)
        logger.info("All wallets completed their tasks!")
