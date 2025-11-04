import re
import asyncio
import requests

from src.gaea_client import GaeaClient
from config import TWO_CAPTCHA_API_URL, TWO_CAPTCHA_API_KEY
from loguru import logger

class TwoCaptcha:
    def __init__(self, client: GaeaClient) -> None:
        self.client = client

    async def create_captcha_task(self):
        logger.debug(f'id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Create captcha task from {TWO_CAPTCHA_API_URL}')

        cloudflare_url = 'https://app.aigaea.net/login' 
        cloudflare_sitekey = '0x4AAAAAAAkhM1uKU9iprx7x'
        # -------------------------------------------------------------------------- 1 createTask
        url = TWO_CAPTCHA_API_URL.rstrip('/')+'/createTask'

        logger.debug(f"url: {url}")
        if len(self.client.proxy_init) > 0:
            proxy_protocol = self.client.proxy_init.split('://')[0]
            proxy_tuple = self.client.proxy_init.split('://')[1]
            proxy_tuple = re.sub(r'^:@', '', proxy_tuple)
            if proxy_tuple.find('@')>0:
                proxy_address, proxy_port = proxy_tuple.split('@')[1].split(':')
                proxy_username, proxy_password = proxy_tuple.split('@')[0].split(':')
            else:
                proxy_address, proxy_port = proxy_tuple.split(':')
                proxy_username = proxy_password = ""
            
        
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} proxy url: {self.client.proxy_init}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} proxy protocol: {proxy_protocol} host: {proxy_address} port: {proxy_port}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} proxy username: {proxy_username} password: {proxy_password}")

            payload = {
                "clientKey": TWO_CAPTCHA_API_KEY,
                "task": {
                    "type": "TurnstileTask",
                    "websiteURL": cloudflare_url,
                    "websiteKey": cloudflare_sitekey,
                    "userAgent": self.client.session.headers['User-Agent'],
                    "proxyType": proxy_protocol,
                    "proxyAddress": proxy_address,
                    "proxyPort": proxy_port,
                    "proxyLogin": proxy_username,
                    "proxyPassword": proxy_password
                }
            }
        else:
            payload = {
                "clientKey": TWO_CAPTCHA_API_KEY,
                "task": {
                    "type": "TurnstileTaskProxyless",
                    "websiteURL": cloudflare_url,
                    "websiteKey": cloudflare_sitekey,
                    "userAgent": self.client.session.headers['User-Agent']
                }
            }

        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} createTask url: {url}")
        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} createTask payload: {payload}")
        response = await self.client.make_request(
            method="POST", 
            url=url, 
            json=payload
        )
        if str(response).find("ERROR") > -1:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} createTask response: {response}")
            return response
        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} createTask response: {response}")

        logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} createTask taskId: {response['taskId']}")

        if response.get('errorId', None):
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: Bad request to 2Captcha(Create Task)")
            return 'ERROR:Bad request to 2Captcha(Create Task)'
            raise Exception('Bad request to 2Captcha(Create Task)')
        return response.get('taskId', None)

    async def getting_captcha_key(self, task_id):
        logger.debug(f'id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Getting captcha key from {TWO_CAPTCHA_API_URL}')

        # -------------------------------------------------------------------------- 2 getTaskResult
        url = TWO_CAPTCHA_API_URL.rstrip('/')+'/getTaskResult'

        payload = {
            "clientKey": TWO_CAPTCHA_API_KEY,
            "taskId": task_id
        }

        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} getTaskResult url: {url}")
        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} getTaskResult payload: {payload}")

        total_time = 5
        timeout = 360
        while True:
            response = await self.client.make_request(
                method="POST", 
                url=url, 
                json=payload
            )
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} getTaskResult run: {round(total_time/5)} response: {response}")
            # if str(response).find("ERROR") > -1:
            #     logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {response}")
            #     return response
            if response.get('errorCode', None):
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: {response['errorCode']} - {response['errorDescription']}")
                return f"ERROR: {response['errorCode']} - {response['errorDescription']}"
            elif response.get('status', None) == 'ready':
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Result taskId: {task_id} ip: {response['ip']} cost: {response['cost']}")
                return response['solution']['token']

            total_time += 5
            await asyncio.sleep(5)

            if total_time > timeout:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: Can`t get captcha solve in 360 second")
                return "ERROR: Can`t get captcha solve in 360 second"
                raise Exception('Can`t get captcha solve in 360 second')
