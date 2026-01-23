import re
import hashlib
import random
import ssl
import asyncio
import socket
import time
from loguru import logger
from aiohttp import ClientSession
from aiohttp_socks import ProxyConnector
from jose import jwt

from utils.helpers import set_data_for_token, is_valid_jwt_format, is_token_valid

def getheaders():
    return {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en,zh-CN;q=0.9,zh;q=0.8,en-US;q=0.7",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Origin": "https://app.gaea.la",
        "Referer": "https://app.gaea.la/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": "Mozilla/5.0 (Linux; Android 12; K) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Safari/537.36",
        "X-Requested-With": "org.telegram.messenger.web",
    }

class GaeaClient:
    def __init__(self, runname: str, id: str, userid: str, email: str, passwd:str, prikey: str, token: str, proxy: str) -> None:
        self.runname = runname
        self.id = id
        self.userid = userid
        self.email = email
        self.prikey = prikey
        self.proxy_init = proxy

        # self.passwd = passwd
        self.passwd = hashlib.sha256(str(passwd).encode()).hexdigest()

        # self.token = token
        ## jwt decode
        if token:  # token
            if not is_valid_jwt_format(token): # 验证token格式
                self.token = ''
                set_data_for_token(runname, self.id, self.token)
                logger.error(f"Invalid token - {self.id}")
            elif not is_token_valid(token): # 验证token是否过期
                self.token = ''
                set_data_for_token(runname, self.id, self.token)
                logger.error(f"Invalid token - {self.id}")
            else:
                self.token = token
        else:
            self.token = ''

        logger.debug(f"id: {id} userid: {userid} email: {email} proxy: {proxy}")
        if len(self.proxy_init) > 0:
            self.session = ClientSession(connector=ProxyConnector.from_url(self.proxy_init, ssl=ssl.create_default_context(), verify_ssl=False))
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
                logger.debug(f"id: {self.id} make_request retry: {int(total_time/30)} url: {url}")
                async with self.session.request( method=method, url=url, headers=headers, data=data, params=params, json=json, ssl=False ) as response:
                    logger.debug(f"id: {self.id} make_request response.status: {response.status}")
                    content_type = response.content_type or ""
                    if response.status in [200, 201]:
                        # data = await response.json()
                        # 根据内容类型决定如何处理响应
                        if 'application/json' in content_type:
                            data = await response.json()
                        else:
                            text = await response.text()
                            # 尝试解析为JSON，如果失败则创建一个包含文本的字典
                            try:
                                data = await response.json()
                            except:
                                data = {"text": text, "content_type": content_type}
                        
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
                    elif response.status in [400,401,402,403,404,405,410,500,503]:
                        # data = await response.json()
                        # 根据内容类型决定如何处理响应
                        if 'application/json' in content_type:
                            data = await response.json()
                        else:
                            text = await response.text()
                            # 尝试解析为JSON，如果失败则创建一个包含文本的字典
                            try:
                                data = await response.json()
                            except:
                                data = {"text": text, "content_type": content_type, "status": response.status}
                        logger.debug(f"id: {self.id} make_request data: {data}")
                        return data
                    raise Exception(f"Bad request to {self.__class__.__name__}({method}) status: {response.status} API: {str(await response.text()).splitlines()[0]}")
            except (socket.gaierror, asyncio.TimeoutError) as error:  # 增加对DNS解析失败和超时的处理
                if int(total_time/30) < 2:
                    logger.debug(f"id: {self.id} make_request retry: {int(total_time/30)} DNS or Timeout ERROR: {str(error).splitlines()[0]} json: {json}")
                else:
                    logger.error(f"id: {self.id} make_request retry: {int(total_time/30)} DNS or Timeout ERROR: {str(error).splitlines()[0]} json: {json}")
                total_time += 30
                if total_time > timeout:
                    return f"ERROR: {error}"
                    raise Exception(error)
                await asyncio.sleep(30)
                continue
            except Exception as error:
                if int(total_time/30) < 2:
                    logger.debug(f"id: {self.id} make_request retry: {int(total_time/30)} except ERROR: {str(error).splitlines()[0]} json: {json}")
                else:
                    logger.error(f"id: {self.id} make_request retry: {int(total_time/30)} except ERROR: {str(error).splitlines()[0]} json: {json}")
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

async def make_request(method:str = 'GET', url:str = None, headers:dict = None, params: dict = None, data:str = None, json:dict = None, module_name: str = 'Request'):
    errors = None
    total_time = 0
    timeout = 100
    while True:
        try:
            logger.debug(f"make_request retry: {int(total_time/30)} url: {url}")
            async with ClientSession() as session:
                async with session.request( method=method, url=url, headers=headers, data=data, params=params, json=json, ssl=False ) as response:
                    logger.debug(f"make_request response.status: {response.status}")
                    content_type = response.content_type or ""
                    if response.status in [200, 201]:
                        # data = await response.json()
                        # 根据内容类型决定如何处理响应
                        if 'application/json' in content_type:
                            data = await response.json()
                        else:
                            text = await response.text()
                            # 尝试解析为JSON，如果失败则创建一个包含文本的字典
                            try:
                                data = await response.json()
                            except:
                                data = {"text": text, "content_type": content_type}
                        
                        if isinstance(data, dict):
                            errors = data.get('errors', None)
                        elif isinstance(data, list) and isinstance(data[0], dict):
                            errors = data[0].get('errors', None)
                        # logger.debug(f"make_request data: {data}")
                        # logger.debug(f"make_request errors: {errors}")

                        if not errors:
                            return data
                        elif 'have been marked as inactive' in f"{errors}":
                            raise Exception(f"Bad request to ({method}) 1 API: {str(errors[0]['message']).splitlines()[0]}")
                        else:
                            raise Exception(f"Bad request to ({method}) 2 API: {str(errors[0]['message']).splitlines()[0]}")
                    elif response.status in [400,401,402,403,404,405,410,500,503]:
                        # data = await response.json()
                        # 根据内容类型决定如何处理响应
                        if 'application/json' in content_type:
                            data = await response.json()
                        else:
                            text = await response.text()
                            # 尝试解析为JSON，如果失败则创建一个包含文本的字典
                            try:
                                data = await response.json()
                            except:
                                data = {"text": text, "content_type": content_type, "status": response.status}
                        logger.debug(f"make_request data: {data}")
                        return data
                    raise Exception(f"Bad request to ({method}) status: {response.status} API: {str(await response.text()).splitlines()[0]}")
        except (socket.gaierror, asyncio.TimeoutError) as error:  # 增加对DNS解析失败和超时的处理
            if int(total_time/30) < 2:
                logger.debug(f"make_request retry: {int(total_time/30)} DNS or Timeout ERROR: {str(error).splitlines()[0]} json: {json}")
            else:
                logger.error(f"make_request retry: {int(total_time/30)} DNS or Timeout ERROR: {str(error).splitlines()[0]} json: {json}")
            total_time += 30
            if total_time > timeout:
                return f"ERROR: {error}"
                raise Exception(error)
            await asyncio.sleep(30)
            continue
        except Exception as error:
            if int(total_time/30) < 2:
                logger.debug(f"make_request retry: {int(total_time/30)} except ERROR: {str(error).splitlines()[0]} json: {json}")
            else:
                logger.error(f"make_request retry: {int(total_time/30)} except ERROR: {str(error).splitlines()[0]} json: {json}")
            if "Proxy connection timed out" in f"{error}":
                retry_flag=True
            elif "General SOCKS server failure" in f"{error}":
                retry_flag=True
            elif "Invalid authentication response" in f"{error}":
                retry_flag=True
            elif "0 bytes read on a total of 2 expected bytes" in f"{error}":
                retry_flag=True
            elif f"Bad request to ({method})" in f"{error}":
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
