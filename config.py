import os
import json
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
# DELAY
SNAIL_UNIT = int(os.getenv("SNAIL_UNIT", default=1800))  # 延迟单位，秒

# CAPTCHA
TWO_CAPTCHA_API_URL = os.getenv("TWO_CAPTCHA_API_URL", default="https://api.2captcha.com")
TWO_CAPTCHA_API_KEY = os.getenv("TWO_CAPTCHA_API_KEY", default="")
CAPTCHA_KEY = os.getenv("CAPTCHA_KEY", default="")

# ERA3 ONLINE
ERA3_ONLINE_STAMP=int(os.getenv("ERA3_ONLINE_STAMP", default=1746806400))  # 第3季上线时间  2025-05-10 00:00:00
EMOTION3_ONLINE_STAMP=int(os.getenv("EMOTION3_ONLINE_STAMP", default=1765382400))  # emotion3上线时间  2025-12-11 00:00:00

# REGISTER
REFERRAL_CODE = get_envsion("REFERRAL_CODE")
# GODHOODID
REFERRAL_ADDRESS = get_envsion("REFERRAL_ADDRESS")
# FUNDS POOLING
POOLING_ADDRESS = os.getenv("POOLING_ADDRESS", default='{}')

# contract
WEB3_RPC_FIXED=os.getenv("WEB3_RPC_FIXED", default="")
WEB3_RPC=os.getenv("WEB3_RPC", default="https://mainnet.base.org")
WEB3_CHAINID=int(os.getenv("WEB3_CHAINID", default=8453))
CONTRACT_USDC=os.getenv("CONTRACT_USDC", default="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
CONTRACT_SXP=os.getenv("CONTRACT_SXP", default="0x31904F19350eE068F186c0d65B25DE9Bf6997c8e")
CONTRACT_TICKET=os.getenv("CONTRACT_TICKET", default="0x565469C6dfeE79d12F9E9E5E0E70777ff3A57639")
CONTRACT_INVITE=os.getenv("CONTRACT_INVITE", default="0xb281bd54ff436b19c285df1b98782c7bec737c72")
CONTRACT_EMOTION=os.getenv("CONTRACT_EMOTION", default="0x85e87202d9ee36Cb18766E4fA65979Cd8fA8767a")
CONTRACT_REWARD=os.getenv("CONTRACT_REWARD", default="0x25D066a8D8D6d386479238f9D05D080D9E5930B1")
CONTRACT_CHOICE=os.getenv("CONTRACT_CHOICE", default="0x8817ac79bA24E60cf812916A78eF5362389FaA3A")
CONTRACT_AWARD=os.getenv("CONTRACT_AWARD", default="0x325BD1751eE8E84fE6c77e4543adD95857EAE1b5")
CONTRACT_SNFTMINT=os.getenv("CONTRACT_SNFTMINT", default="0xdc37b93628719778663d5ac36d2171ce471a9b7e")
CONTRACT_ANFTMINT=os.getenv("CONTRACT_ANFTMINT", default="0x1ac341d729e01c271Db3B8bCfD2e26172439f614")
