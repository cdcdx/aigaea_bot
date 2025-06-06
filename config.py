import os
from dotenv import find_dotenv, load_dotenv, get_key, set_key

load_dotenv(find_dotenv('.env'))

def get_envsion(key, format=True):
    if format:
        value = []
        valueStr = get_key(find_dotenv('.env'), key_to_get=key)
        if valueStr != None:
            value = valueStr.split(',')
    else:
        value = get_key(find_dotenv('.env'), key_to_get=key)
    return value

def set_envsion(key, value, format=True):
    if format:
        valueStr = ','.join(value)
    else:
        valueStr = value
    return set_key(find_dotenv('.env'), key_to_set=key, value_to_set=valueStr)

# GAEA
GAEA_API = os.getenv("GAEA_API", default="https://api.aigaea.net")

# CAPTCHA
TWO_CAPTCHA_API_URL = os.getenv("TWO_CAPTCHA_API_URL", default="https://api.2captcha.com")
TWO_CAPTCHA_API_KEY = os.getenv("TWO_CAPTCHA_API_KEY", default="")
CAPTCHA_KEY = os.getenv("CAPTCHA_KEY", default="")
REFERRAL_CODE = get_envsion("REFERRAL_CODE")
REFERRAL_ADDRESS = get_envsion("REFERRAL_ADDRESS")

ERA3_ONLINE_STAMP=int(os.getenv("ERA3_ONLINE_STAMP", default=1746806400))  # 第3季上线时间  2025-05-10 00:00:00

WEB3_RPC_FIXED=os.getenv("WEB3_RPC_FIXED", default="")
# contract
WEB3_RPC=os.getenv("WEB3_RPC", default="https://mainnet.base.org")
WEB3_CHAINID=int(os.getenv("WEB3_CHAINID", default=8453))
CONTRACT_USDC=os.getenv("CONTRACT_USDC", default="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
CONTRACT_INVITE=os.getenv("CONTRACT_INVITE", default="0xb281bd54ff436b19c285df1b98782c7bec737c72")
CONTRACT_EMOTION=os.getenv("CONTRACT_EMOTION", default="0xf6622690902823dc785065cbe5ff30261d28beb7")
CONTRACT_REWARD=os.getenv("CONTRACT_REWARD", default="0x5cd240574393baeb26870069314308490dddd3c3")
