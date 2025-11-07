import re
import time
import dns.resolver
from loguru import logger

from src.gaea_client import GaeaClient, getheaders, make_request
from utils.get_capcha_key import TwoCaptcha
from config import set_envsion, GAEA_API, ERA3_ONLINE_STAMP
from config import WEB3_RPC, WEB3_RPC_FIXED, WEB3_CHAINID, CONTRACT_USDC, CONTRACT_SXP, CONTRACT_TICKET, CONTRACT_EMOTION, CONTRACT_REWARD

async def get_captcha_key(client: GaeaClient):
    two_captcha = TwoCaptcha(client)
    task_id = await two_captcha.create_captcha_task()
    return await two_captcha.getting_captcha_key(task_id=task_id)

def update_web3_config(config):
    current_timestamp = int(time.time())
    logger.debug(f"current_timestamp: {current_timestamp} ERA3_ONLINE_STAMP: {ERA3_ONLINE_STAMP}")

    set_envsion("WEB3_RPC", config.get("rpc"), format=False)
    set_envsion("WEB3_CHAINID", str(config.get("chain_id")), format=False)
    set_envsion("CONTRACT_USDC", config.get("usd"), format=False)
    set_envsion("CONTRACT_SXP", config.get("sxp"), format=False)
    set_envsion("CONTRACT_TICKET", config.get("ticket"), format=False)
    set_envsion("CONTRACT_INVITE", config.get("invite"), format=False)
    set_envsion("CONTRACT_SNFTMINT", config.get("snftmint"), format=False)
    set_envsion("CONTRACT_ANFTMINT", config.get("anftmint"), format=False)
    
    if ERA3_ONLINE_STAMP < current_timestamp and "emotion2" in config:
        set_envsion("CONTRACT_EMOTION", config.get("emotion2"), format=False)
        set_envsion("CONTRACT_REWARD", config.get("reward2"), format=False)
    else:
        set_envsion("CONTRACT_EMOTION", config.get("emotion"), format=False)
        set_envsion("CONTRACT_REWARD", config.get("reword"), format=False)
    
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
    if ERA3_ONLINE_STAMP < current_timestamp and "emotion2" in config:
        CONTRACT_EMOTION = config["emotion2"]
        CONTRACT_REWARD = config["reward2"]
    else:
        CONTRACT_EMOTION = config["emotion"]
        CONTRACT_REWARD = config["reword"]
    logger.info(f"update_web3_config - CHAINID: {WEB3_CHAINID} RPC: {WEB3_RPC} EMOTION: {CONTRACT_EMOTION} REWARD: {CONTRACT_REWARD} USDC: {CONTRACT_USDC}")

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
