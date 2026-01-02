import re
import time
import random
import dns.resolver
from loguru import logger
from questionary import Choice, select, text

from src.gaea_client import GaeaClient, getheaders, make_request
from utils.get_capcha_key import TwoCaptcha
from config import set_envsion, GAEA_API, ERA3_ONLINE_STAMP, EMOTION3_ONLINE_STAMP
from config import WEB3_RPC, WEB3_RPC_FIXED, WEB3_CHAINID, CONTRACT_USDC, CONTRACT_SXP, CONTRACT_TICKET, CONTRACT_EMOTION, CONTRACT_REWARD

async def get_captcha_key(client: GaeaClient):
    two_captcha = TwoCaptcha(client)
    task_id = await two_captcha.create_captcha_task()
    return await two_captcha.getting_captcha_key(task_id=task_id)

def update_web3_config(config):
    current_timestamp = int(time.time())
    logger.debug(f"current_timestamp: {current_timestamp} ERA3_ONLINE_STAMP: {ERA3_ONLINE_STAMP} EMOTION3_ONLINE_STAMP: {EMOTION3_ONLINE_STAMP}")

    set_envsion("WEB3_RPC", config.get("rpc"), format=False)
    set_envsion("WEB3_CHAINID", str(config.get("chain_id")), format=False)
    set_envsion("CONTRACT_USDC", config.get("usd"), format=False)
    set_envsion("CONTRACT_SXP", config.get("sxp"), format=False)
    set_envsion("CONTRACT_TICKET", config.get("ticket"), format=False)
    set_envsion("CONTRACT_INVITE", config.get("invite"), format=False)
    set_envsion("CONTRACT_SNFTMINT", config.get("snftmint"), format=False)
    set_envsion("CONTRACT_ANFTMINT", config.get("anftmint"), format=False)
    
    if ERA3_ONLINE_STAMP > current_timestamp:
        set_envsion("CONTRACT_EMOTION", config.get("emotion"), format=False)
        set_envsion("CONTRACT_REWARD", config.get("reward"), format=False)
    elif EMOTION3_ONLINE_STAMP > current_timestamp:
        set_envsion("CONTRACT_EMOTION", config.get("emotion2"), format=False)
        set_envsion("CONTRACT_REWARD", config.get("reward2"), format=False)
    else:
        set_envsion("CONTRACT_EMOTION", config.get("emotion3"), format=False)
        set_envsion("CONTRACT_REWARD", config.get("reward3"), format=False)
    
    set_envsion("CONTRACT_CHOICE", config.get("choice2"), format=False)
    set_envsion("CONTRACT_AWARD", config.get("award2"), format=False)

    WEB3_RPC = config["rpc"] if WEB3_RPC_FIXED=='' else WEB3_RPC_FIXED
    WEB3_CHAINID = config["chain_id"]
    CONTRACT_USDC = config["usd"]
    CONTRACT_SXP = config["sxp"]
    CONTRACT_TICKET = config["ticket"]
    CONTRACT_INVITE = config["invite"]
    CONTRACT_SNFTMINT = config["snftmint"]
    CONTRACT_ANFTMINT = config["anftmint"]
    if ERA3_ONLINE_STAMP > current_timestamp:
        CONTRACT_EMOTION = config["emotion"]
        CONTRACT_REWARD = config["reword"]
    elif EMOTION3_ONLINE_STAMP > current_timestamp:
        CONTRACT_EMOTION = config["emotion2"]
        CONTRACT_REWARD = config["reward2"]
    else:
        CONTRACT_EMOTION = config["emotion3"]
        CONTRACT_REWARD = config["reward3"]
    logger.info(f"update_web3_config - CHAINID: {WEB3_CHAINID} RPC: {WEB3_RPC} USDC: {CONTRACT_USDC}")

async def get_web3_config():
    try:
        headers = getheaders()
        # -------------------------------------------------------------------------- web3_config
        url = GAEA_API.rstrip('/')+'/api/godhood/web3_config'

        logger.debug(f"get_web3_config url: {url}")
        response = await make_request(
            method="GET", 
            url=url, 
            headers=headers
        )
        if 'ERROR' in response:
            logger.error(f"get_web3_config response: {response}")
            raise Exception(response)
        # logger.debug(f"get_web3_config response: {response}")

        code = response.get('code', None)
        if code in [200, 201]:
            logger.debug(f"get_web3_config data => {response['data']}")
            web3_config = None
            if response['data']:
                if response['data']['network'] and response['data']['config']:
                    for config in response['data']['config']:
                        if config['network'] == response['data']['network']:
                            web3_config = config
            logger.debug(f"get_web3_config web3_config => {web3_config}")

            if web3_config:
                # 保存到config
                update_web3_config(web3_config)

            return web3_config
        else:
            message = response.get('msg', None)
            if message is None:
                message = f"{response.get('detail', None)}" 
            if message.find('completed') > 0:
                logger.info(f"get_web3_config => {message}")
                return message
            else:
                logger.debug(f"get_web3_config ERROR: {message}")
                raise Exception(message)
    except Exception as error:
        logger.error(f"get_web3_config except: {error}")

def is_valid_ip(ip: str) -> bool:
    # Regular expression for validating an IPv4/IPv6 address
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ipv6_pattern = re.compile(r'^(([0-9a-fA-F]{1,4}):){7}([0-9a-fA-F]{1,4})$')
    if ipv4_pattern.match(ip):
        # Further check to ensure each octet is between 0 and 255
        parts = ip.split('.')
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    elif ipv6_pattern.match(ip):
        return True
    else:
        return False

async def resolve_domain(url):
    parsed_url = url.split('/')[2]  # 提取域名部分
    domain = parsed_url.split(':')[0]  # 提取域名部分
    if is_valid_ip(domain):
        logger.debug(f"Domain {domain} is IP address.")
        return None
    try:
        logger.debug(f"Domain {domain} is being resolved.")
        answers = dns.resolver.resolve(domain, 'A')
        logger.debug(f"Domain {domain} resolved to {answers}.")
        return [answer.address for answer in answers]
    except dns.resolver.NXDOMAIN:
        logger.error(f"Domain {domain} does not exist.")
        return None
    except dns.resolver.NoNameservers:
        logger.error(f"No nameservers found for domain {domain}.")
        return None
    except Exception as error:
        logger.error(f"resolve_domain except ERROR: {str(error)}")
        return None

# ---------------------------------------------------------------------------------------------------------- input

def choose_emotion():
    emotion_int = select(
        'Choose Emotion',
        choices=[
            Choice("Random",   '0', shortcut_key="0"),
            Choice("Postive",  '1', shortcut_key="1"),
            Choice("Neutral",  '2', shortcut_key="2"),
            Choice("Negative", '3', shortcut_key="3"),
            Choice("deep.txt", '9', shortcut_key="9"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    return emotion_int

def choose_task_emotion():
    task_emotion = select(
        'Choose Task',
        choices=[
            Choice("No AI",        '0', shortcut_key="0"),
            Choice("No Train",     '1', shortcut_key="1"),
            Choice("DeepTrain",    '2', shortcut_key="2"),
            Choice("TicketTrain",  '3', shortcut_key="3"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    return task_emotion

def choose_choice():
    choice_int = select(
        'Choose Choice',
        choices=[
            Choice("Random",      '0', shortcut_key="0"),
            Choice("Safeguarding",'1', shortcut_key="1"),
            Choice("Balancing",   '2', shortcut_key="2"),
            Choice("Advancing",   '3', shortcut_key="3"),
            Choice("Leaping",     '4', shortcut_key="4"),
            Choice("deep.txt",    '9', shortcut_key="9"),
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

def choose_ticket_level():
    task_ticket_level = select(
        'Choose Ticket',
        choices=[
            Choice("No ticket",          '0', shortcut_key="0"),
            Choice("Level 1 - 1.99 U",   '1', shortcut_key="1"),
            Choice("Level 2 - 19.9 U",   '2', shortcut_key="2"),
            Choice("Level 3 - 69.9 U",   '3', shortcut_key="3"),
            Choice("Level 4 - 0.4 U",    '4', shortcut_key="4"),
            # Choice("Level 3 - 39.9 U",   '3', shortcut_key="3"),
            # Choice("Level 4 - 99.9 U",   '4', shortcut_key="4"),
        ],
        use_shortcuts=True,
        use_arrow_keys=True,
    ).ask()
    return task_ticket_level

def input_ticket():
    task_ticket = text(
        'burn ticket (0-No Ticket, 1~200):'
    ).ask()
    
    if task_ticket is None:  # 用户按了 Ctrl+C
        return '0'
    
    return task_ticket.strip()

def random_ticket():
    task_random = text(
        'random ticket (0-No random, 1~200):'
    ).ask()
    
    if task_random is None:  # 用户按了 Ctrl+C
        return '0'
    
    return task_random.strip()

# ----------------------------------------------------------------------------------------------------------

def generate_random_groups():
    """
    随机生成100组7个浮点数，每组7个浮点数求和为100
    """
    groups = []
    
    for _ in range(100):
        # 生成6个随机数
        numbers = [random.uniform(0, 100) for _ in range(6)]
        
        # 计算这6个数的总和
        sum_of_six = sum(numbers)
        
        # 第7个数为100减去前6个数的总和
        seventh_number = 100 - sum_of_six
        
        # 将第7个数添加到列表中
        numbers.append(seventh_number)
        
        # 如果第7个数小于0或大于100，需要重新生成
        if seventh_number < 0 or seventh_number > 100:
            # 使用另一种方法：先生成7个随机正数，然后归一化到总和为100
            positive_numbers = [random.uniform(0.1, 100) for _ in range(7)]
            total = sum(positive_numbers)
            numbers = [(num / total) * 100 for num in positive_numbers]
        
        groups.append(numbers)
    
    return groups

