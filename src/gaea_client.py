import re
import hashlib
import random
import ssl
import asyncio
import time
from loguru import logger
from aiohttp import ClientSession
from aiohttp_socks import ProxyConnector
from jose import jwt

class GaeaClient:
    def __init__(self, id: str, userid: str, email: str, passwd:str, prikey: str, token: str, proxy: str) -> None:
        self.id = id
        self.userid = userid
        self.email = email
        self.prikey = prikey
        self.proxy_init = proxy

        # self.passwd = passwd
        self.passwd = hashlib.sha256(str(passwd).encode()).hexdigest()

        # self.token = token
        ## jwt decode
        if len(token)>20 and len(token.split('.')) == 3:
            payload = jwt.get_unverified_claims(token)
            logger.debug(f"payload: {payload}")
            current_timestamp = int(time.time())
            expire = payload.get("expire")
            if expire is None or expire <= current_timestamp:
                self.token = ''
            else:
                self.token = token
        else:
            self.token = ''

        logger.debug(f"id: {id} userid: {userid} email: {email} proxy: {proxy}")
        if len(self.proxy_init) > 0:
            self.session = ClientSession(connector=ProxyConnector.from_url(self.proxy_init, ssl=ssl.create_default_context(), verify_ssl=True))
        else:
            self.session = ClientSession()
        self.session.headers.update({
            'User-Agent': self.get_user_agent()
        })

    @staticmethod
    def get_user_agent():
        random_version = f"{random.uniform(520, 540):.2f}"
        return (f'Mozilla/5.0 (Linux; Android 14; sdk_gphone64_arm64 Build/UE1A.230829.036.A2; wv) AppleWebKit/{random_version} (KHTML, like Gecko) Version/4.0 Chrome/121.0.0.0 Mobile Safari/{random_version}')

    async def make_request(self, method:str = 'GET', url:str = None, headers:dict = None, params: dict = None, data:str = None, json:dict = None, module_name: str = 'Request'):

        errors = None

        total_time = 0
        timeout = 100
        while True:
            try:
                logger.debug(f"id: {self.id} make_request retry:{int(total_time/30)} url: {url}")
                async with self.session.request(
                        method=method, url=url, headers=headers, data=data, params=params, json=json, ssl=False
                ) as response:
                    logger.debug(f"id: {self.id} make_request response.status: {response.status}")
                    if response.status in [200, 201]:
                        data = await response.json()
                        if isinstance(data, dict):
                            errors = data.get('errors', None)
                        elif isinstance(data, list) and isinstance(data[0], dict):
                            errors = data[0].get('errors', None)
                        # logger.debug(f"id: {self.id} make_request data: {data}")
                        # logger.debug(f"id: {self.id} make_request errors: {errors}")

                        if not errors:
                            return data
                        elif 'have been marked as inactive' in f"{errors}":
                            raise Exception(f"Bad request to {self.__class__.__name__}({method}) 1 API: {str(errors[0]['message']).splitlines()[0]}")
                        else:
                            raise Exception(f"Bad request to {self.__class__.__name__}({method}) 2 API: {str(errors[0]['message']).splitlines()[0]}")
                    elif response.status in [400,401,402,403,404,405,410,500]:
                        data = await response.json()
                        logger.debug(f"id: {self.id} make_request data: {data}")
                        return data
                    raise Exception(f"Bad request to {self.__class__.__name__}({method}) status: {response.status} API: {str(await response.text()).splitlines()[0]}")
            except Exception as error:
                logger.error(f"id: {self.id} make_request retry:{int(total_time/30)} except ERROR: {str(error).splitlines()[0]} json: {json}")
                if "Proxy connection timed out" in f"{error}":
                    retry_flag=True
                elif "General SOCKS server failure" in f"{error}":
                    retry_flag=True
                elif "Invalid authentication response" in f"{error}":
                    retry_flag=True
                elif "0 bytes read on a total of 2 expected bytes" in f"{error}":
                    retry_flag=True
                elif f"Bad request to {self.__class__.__name__}({method})" in f"{error}":
                    retry_flag=True
                elif "Server disconnected" in f"{error}":
                    retry_flag=False
                    return f"SUCCESS: ERROR: {error}"
                elif "Couldn't connect to proxy" in f"{error}":
                    retry_flag=False
                    return f"SUCCESS: ERROR: {error}"
                elif "WinError" in f"{error}":
                    retry_flag=False
                    return f"SUCCESS: ERROR: {error}"
                else:
                    retry_flag=False
                    return f"ERROR: {error}"

                if retry_flag:
                    total_time += 30
                    if total_time > timeout:
                        return f"ERROR: {error}"
                        raise Exception(error)
                    await asyncio.sleep(30)
                    continue
                else:
                    return f"ERROR: {error}"
                    raise Exception(error)
