import re
import dns.resolver
from loguru import logger
from src.gaea_client import GaeaClient
from utils.get_capcha_key import TwoCaptcha

async def get_captcha_key(client: GaeaClient):
    two_captcha = TwoCaptcha(client)
    task_id = await two_captcha.create_captcha_task()
    return await two_captcha.getting_captcha_key(task_id=task_id)

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
