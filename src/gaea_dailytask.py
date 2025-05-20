import re
import os
import time
import uuid
import requests
import asyncio
import random
import base64
import hashlib
import json
import datetime
from datetime import datetime as dt
from loguru import logger
from web3 import Web3
from eth_account.messages import encode_defunct

from src.gaea_client import GaeaClient
from utils.contract_abi import contract_abi_usdc, contract_abi_emotion, contract_abi_emotion2, contract_abi_invite
from utils.decorators import helper
from utils.helpers import get_data_for_token, set_data_for_token, set_data_for_userid
from utils.services import get_captcha_key
from config import get_envsion, set_envsion, GAEA_API, ERA3_ONLINE_STAMP
from config import WEB3_RPC, WEB3_CHAINID, CONTRACT_USDC, CONTRACT_INVITE, CONTRACT_EMOTION, CAPTCHA_KEY, REFERRAL_CODE, REFERRAL_ADDRESS

class GaeaDailyTask:
    def __init__(self, client: GaeaClient) -> None:
        self.client = client

    def getheaders(self):
        return {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en,zh-CN;q=0.9,zh;q=0.8,en-US;q=0.7",
            "Authorization": f"Bearer {self.client.token}",
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

    # Send transaction (retry 5 times, 2 seconds each)
    def send_transaction_with_retry(self, web3_obj, transaction, max_fee_per_gas, priority_fee_per_gas, max_retries=1, retry_interval=2):
        """
        发送交易
        :param web3_connection: Web3 连接对象
        :param transaction: 交易对象
        :param max_fee_per_gas: 最大每 gas 费用
        :param priority_fee_per_gas: 优先每 gas 费用
        :param max_retries: 最大重试次数
        :param retry_interval: 重试间隔时间
        :return: 交易结果和交易哈希
        """
        attempt = 0
        while attempt < max_retries:
            try:
                gas_limit = web3_obj.eth.estimate_gas(transaction)
                logger.info(f"Estimated GasLimit: {gas_limit} units")
                total_gas_cost = max_fee_per_gas * gas_limit
                logger.info(f"Total Gas Cost: {total_gas_cost} wei / {total_gas_cost / 10 ** 18} ETH")
                transaction.update({
                    "gas": gas_limit,
                    "maxFeePerGas": max_fee_per_gas,
                    "maxPriorityFeePerGas": priority_fee_per_gas,
                })
                logger.info(f"update transaction: {transaction}")
                signed_transaction = web3_obj.eth.account.sign_transaction(transaction, self.client.prikey)
                logger.debug(f"signed_transaction: {signed_transaction}")
                try:
                    # Sending transactions
                    if str(signed_transaction).find("raw_transaction") > 0:
                        tx_hash = web3_obj.eth.send_raw_transaction(signed_transaction.raw_transaction)
                    elif str(signed_transaction).find("signed_transaction") > 0:
                        tx_hash = web3_obj.eth.send_raw_transaction(signed_transaction.raw_transaction)
                    logger.info(f"Send transaction, hash: {tx_hash.hex()}")
                    # Waiting for the transaction to complete
                    receipt = web3_obj.eth.wait_for_transaction_receipt(tx_hash)
                    logger.info(f"Waiting for completion, receipt: {receipt}")
                    tx_bytes = f"0x{tx_hash.hex()}"
                    
                    if receipt["status"] == 1:
                        logger.info(f"Transaction successful, hash: {tx_bytes}")
                        return True, {"tx_hash": tx_bytes}
                    else:
                        logger.error(f"Transaction failed, hash: {tx_bytes}")
                        return False, {"tx_hash": tx_bytes}
                except ValueError as e:
                    logger.info(f"Failed to transfer ValueError ETH : {str(e)}")
                    try:
                        if e.args[0].get('message') in 'intrinsic gas too low':
                            result = False, {"tx_hash": tx_bytes, "msg": e.args[0].get('message')}
                        else:
                            result = False, {"tx_hash": tx_bytes, "msg": e.args[0].get('message'), "code": e.args[0].get('code')}
                    except Exception as e:
                        result = False, {"tx_hash": tx_bytes, "msg": str(e)}
                    return result
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {e}")
                attempt += 1
                if attempt < max_retries:
                    logger.debug(f"Retrying in {retry_interval} seconds...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Max retries reached. Failed to eth.estimate_gas: {str(e)}")
                    return False, {"tx_hash": "estimate_gas", "msg": str(e)}

    # --------------------------------------------------------------------------

    # 60 seconds
    async def register_clicker(self) -> None:
        try:
            headers = self.getheaders()
            headers.pop('Authorization', None)

            # -------------------------------------------------------------------------- captcha
            capcha_key = CAPTCHA_KEY if CAPTCHA_KEY else ''
            if capcha_key == '':
                total_time = 0
                timeout = 100
                retry_flag=False
                while True:
                    try:
                        capcha_key = await get_captcha_key(client=self.client)
                        if str(capcha_key).find("ERROR") > -1:
                            raise f"{capcha_key}"
                        break
                    except Exception as error:
                        logger.error(f"id: {self.client.id} get_captcha_key retry: {int(total_time/30)} except ERROR: {str(error).splitlines()[0]} ")
                        if "Proxy connection timed out" in f"{error}":
                            retry_flag=True
                        elif "Workers could not solve the Captcha" in f"{error}":
                            retry_flag=True
                        else:
                            retry_flag=False
                        if retry_flag:
                            total_time += 30
                            if total_time > timeout:
                                return f"{error}"
                            await asyncio.sleep(30)
                            continue
                        else:
                            return f"{error}"
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} get_captcha_key finished")

            logger.debug(f"capcha_key: {capcha_key}")
            # -------------------------------------------------------------------------- username
            username = self.client.email.split('@')[0]
            url = GAEA_API.rstrip('/')+'/api/validate/username'
            json_data = {
                "username": username
            }
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker {response}")

            code = response.get('code', None)
            if code not in [200, 201]:
                username = self.client.email
            
            delay = random.randint(5, 10)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- register
            url = GAEA_API.rstrip('/')+'/api/auth/register'
            json_data = {
                "email": self.client.email,
                "username": username,
                "password": self.client.passwd,
                "referral_code": random.choice(REFERRAL_CODE) if REFERRAL_CODE else "gaKJUXBVLa08Ad",
                "recaptcha_token": capcha_key
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker except: {error}")

    async def login_clicker(self) -> None:
        try:
            headers = self.getheaders()
            headers.pop('Authorization', None)

            # -------------------------------------------------------------------------- captcha
            capcha_key = CAPTCHA_KEY if CAPTCHA_KEY else ''
            if capcha_key == '':
                total_time = 0
                timeout = 100
                retry_flag=False
                while True:
                    try:
                        capcha_key = await get_captcha_key(client=self.client)
                        if str(capcha_key).find("ERROR") > -1:
                            raise f"{capcha_key}"
                        break
                    except Exception as error:
                        logger.error(f"id: {self.client.id} get_captcha_key retry: {int(total_time/30)} except ERROR: {str(error).splitlines()[0]} ")
                        if "Proxy connection timed out" in f"{error}":
                            retry_flag=True
                        elif "Workers could not solve the Captcha" in f"{error}":
                            retry_flag=True
                        else:
                            retry_flag=False
                        if retry_flag:
                            total_time += 30
                            if total_time > timeout:
                                return f"{error}"
                            await asyncio.sleep(30)
                            continue
                        else:
                            return f"{error}"
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} get_captcha_key finished")

            logger.debug(f"capcha_key: {capcha_key}")
            # -------------------------------------------------------------------------- login
            url = GAEA_API.rstrip('/')+'/api/auth/login'
            json_data = {
                "username": self.client.email,
                "password": self.client.passwd,
                "remember_me": True,
                "recaptcha_token": capcha_key
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker except: {error}")

    async def session_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- session
            url = GAEA_API.rstrip('/')+'/api/auth/session'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session_clicker url: {url}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session_clicker except: {error}")

    async def earninfo_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- earninfo
            url = GAEA_API.rstrip('/')+'/api/earn/info'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo_clicker except: {error}")

    async def godhoodinfo_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- godhoodinfo
            url = GAEA_API.rstrip('/')+'/api/godhood/info'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo_clicker except: {error}")

    async def era3info_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- era3info
            url = GAEA_API.rstrip('/')+'/api/ranking/era3?page=1&limit=20'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3info_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3info_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3info_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['user']}")
                return response['user']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3info_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3info_clicker ERROR: {message}")
                    raise Exception(message)
            
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3info_clicker except: {error}")

    async def blindbox_list_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- blindbox_list
            url = GAEA_API.rstrip('/')+'/api/godhood/blindbox/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                datas = response['data']
                total = response['total']
                cdkeys = []
                if total >= 10:
                    for i in range(10):
                        cdkeys.append(datas[i]['cdkey'])
                else:
                    cdkeys.append(datas[0]['cdkey'])
                return {'cdkeys': cdkeys}
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker except: {error}")

    async def blindbox_open_clicker(self, cdkeys) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- blindbox_open
            url = GAEA_API.rstrip('/')+'/api/godhood/blindbox/open'
            json_data = {
                "cdkey": cdkeys
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker except: {error}")

    async def referral_list_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- referral_list
            url = GAEA_API.rstrip('/')+'/api/reward/referral-list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list_clicker ERROR: {message}")
                    raise Exception(message)
            
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list_clicker except: {error}")

    async def referral_complete_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- referral_complete
            url = GAEA_API.rstrip('/')+'/api/reward/referral-complete'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete_clicker url: {url}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete_clicker except: {error}")

    async def bind_address_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # -------------------------------------------------------------------------- address
            sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # -------------------------------------------------------------------------- bind_address
            url = GAEA_API.rstrip('/')+'/api/bind/address'
            json_data = {
                "address": sender_address
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker except: {error}")

    async def godhoodemotion_clicker(self) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            # -------------------------------------------------------------------------- godhoodid
            web3_obj = Web3(Web3.HTTPProvider(WEB3_RPC))
            # 连接rpc节点
            connected = web3_obj.is_connected()
            if not connected:
                logger.error(f"Ooops! Failed to eth.is_connected.")
                raise Exception("Failed to eth.is_connected.")
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} white_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 购卡合约地址
            invite_address = Web3.to_checksum_address(CONTRACT_INVITE)
            invite_contract = web3_obj.eth.contract(address=invite_address, abi=contract_abi_invite)
        
            # 当前是否购卡
            is_godhoodid = invite_contract.functions.isgodhoodID( sender_address ).call()
            logger.debug(f"is_godhoodid: {is_godhoodid}")

            if is_godhoodid is None: # 
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please mint GODHOOD ID first | godhoodid: {is_godhoodid}")
                return 'Please mint GODHOOD ID first'

            headers = self.getheaders()
            # -------------------------------------------------------------------------- godhood_emotion
            url = GAEA_API.rstrip('/')+'/api/godhood/emotion'
            json_data = {
                "emotion_code": "INTJ",
                "emotion_detail": {"type": "INTJ", "EI_E_ratio": "32", "EI_I_ratio": "32", "SN_N_ratio": "37", "SN_S_ratio": "57", "emotion_code": "INTJ"}
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker except: {error}")

    # --------------------------------------------------------------------------

    async def checkin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- checkin
            url = GAEA_API.rstrip('/')+'/api/mission/complete-mission'
            json_data = {
                "mission_id": "1"
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker except: {error}")

    async def signin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- signin
            url = GAEA_API.rstrip('/')+'/api/signin/complete'
            json_data = {
                "detail": "Positive_Love"
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker except: {error}")

    async def dailylist_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- dailylist
            url = GAEA_API.rstrip('/')+'/api/reward/daily-list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker except: {error}")

    async def dailycheckin_clicker(self, randint) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- dailycheckin
            url = GAEA_API.rstrip('/')+'/api/reward/daily-complete'
            # weekday = dt.now().weekday() + 1
            # json_data = {
            #     "id": weekday
            # }
            json_data = {
                "id": randint
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker except: {error}")

    async def medalcheckin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- medalcheckin
            url = GAEA_API.rstrip('/')+'/api/medal/complete'
            json_data = {}

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker except: {error}")

    async def aitrain_clicker(self, emotion_detail) -> None:
        try:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker emotion_detail: {emotion_detail}")

            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- aitrain
            url = GAEA_API.rstrip('/')+'/api/ai/complete'
            json_data = {
                "detail": emotion_detail
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker except: {error}")

    async def ailist_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- ailist
            url = GAEA_API.rstrip('/')+'/api/ai/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker except: {error}")

    async def godhoodid_clicker(self) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            # -------------------------------------------------------------------------- godhoodid
            web3_obj = Web3(Web3.HTTPProvider(WEB3_RPC))
            # 连接rpc节点
            connected = web3_obj.is_connected()
            if not connected:
                logger.error(f"Ooops! Failed to eth.is_connected.")
                raise Exception("Failed to eth.is_connected.")
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} white_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 购卡合约地址
            invite_address = Web3.to_checksum_address(CONTRACT_INVITE)
            invite_contract = web3_obj.eth.contract(address=invite_address, abi=contract_abi_invite)
        
            # 当前是否购卡
            is_godhoodid = invite_contract.functions.isgodhoodID( sender_address ).call()
            logger.debug(f"is_godhoodid: {is_godhoodid}")

            if is_godhoodid: # 
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid already completed | godhoodid: {is_godhoodid}")
                return 'godhoodid already completed'

            # 账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            # 购卡合约授权金额
            sender_allowance_usdc = usdc_contract.functions.allowance(sender_address, invite_address).call()
            logger.debug(f"sender_allowance_usdc: {sender_allowance_usdc}") # 无穷大 115792089237316195423570985008687907853269984665640564039457584007913129.639935

            # USDC余额不足
            inviter_price = 20000000 # 20 USDC
            if inviter_price > sender_balance_usdc:
                logger.error(f"Ooops! Insufficient USDC balance.")
                return "Insufficient USDC balance."
            
            # 购卡合约USDC授权额度不足
            if inviter_price > sender_allowance_usdc:
                logger.error(f"Ooops! Insufficient USDC authorization amount for invite_contract.")
                # raise Exception("Insufficient USDC authorization amount for invite_contract.")

                # 获取当前Gas
                latest_block = web3_obj.eth.get_block('latest')
                if latest_block is None:
                    logger.error(f"Ooops! Failed to eth.get_block.")
                    raise Exception("Failed to eth.get_block.")
                base_fee_per_gas = latest_block['baseFeePerGas']
                priority_fee_per_gas = web3_obj.eth.max_priority_fee  # 获取推荐的小费
                max_fee_per_gas = base_fee_per_gas + priority_fee_per_gas
                logger.info(f"base_fee_per_gas: {base_fee_per_gas} wei")
                logger.info(f"priority_fee_per_gas: {priority_fee_per_gas} wei")
                logger.info(f"max_fee_per_gas: {max_fee_per_gas} wei")

                # 构建交易 - 购卡合约金额授权
                transaction = usdc_contract.functions.approve(invite_address, inviter_price).build_transaction(
                    {
                        "chainId": WEB3_CHAINID,
                        "from": sender_address,
                        "gas": 20000000,  # 最大 Gas 用量
                        "maxFeePerGas": max_fee_per_gas,  # 新的费用参数
                        "maxPriorityFeePerGas": priority_fee_per_gas,  # 新的费用参数
                        "nonce": web3_obj.eth.get_transaction_count(sender_address),
                    }
                )
                logger.debug(f"approve transaction: {transaction}")

                # 发送交易
                tx_success, _ = self.send_transaction_with_retry(web3_obj, transaction, max_fee_per_gas, priority_fee_per_gas)
                if tx_success == False:
                    logger.error(f"Ooops! Failed to send_transaction.")
                    raise Exception("Failed to send_transaction.")
                
                logger.success(f"The approve transaction was send successfully! - transaction: {transaction}")

            # 获取当前Gas
            latest_block = web3_obj.eth.get_block('latest')
            if latest_block is None:
                logger.error(f"Ooops! Failed to eth.get_block.")
                raise Exception("Failed to eth.get_block.")
            base_fee_per_gas = latest_block['baseFeePerGas']
            priority_fee_per_gas = web3_obj.eth.max_priority_fee  # 获取推荐的小费
            max_fee_per_gas = base_fee_per_gas + priority_fee_per_gas
            logger.info(f"base_fee_per_gas: {base_fee_per_gas} wei")
            logger.info(f"priority_fee_per_gas: {priority_fee_per_gas} wei")
            logger.info(f"max_fee_per_gas: {max_fee_per_gas} wei")

            # 构建交易 - 购卡
            referral_addr = random.choice(REFERRAL_ADDRESS) if REFERRAL_ADDRESS else "0x263f8d3722f03b88818389cd6c34c76f17d097a4"
            referral_address = Web3.to_checksum_address(referral_addr)
            logger.debug(f"referral_address: {referral_address}")
            
            transaction = invite_contract.functions.inviter( referral_address ).build_transaction(
                    {
                        "chainId": WEB3_CHAINID,
                        "from": sender_address,
                        "gas": 20000000,  # 最大 Gas 用量
                        "maxFeePerGas": max_fee_per_gas,  # 新的费用参数
                        "maxPriorityFeePerGas": priority_fee_per_gas,  # 新的费用参数
                        "nonce": web3_obj.eth.get_transaction_count(sender_address),
                    }
                )
            logger.debug(f"inviter transaction: {transaction}")

            # 发送交易
            tx_success, _ = self.send_transaction_with_retry(web3_obj, transaction, max_fee_per_gas, priority_fee_per_gas)
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction.")
                raise Exception("Failed to send_transaction.")
            else:
                # -------------------------------------------------------------------------- godhoodemotion
                clicker_response = await self.godhoodemotion_clicker()
                if clicker_response is None:
                    return "ERROR"
                
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            
            logger.success(f"The inviter transaction was send successfully! - transaction: {transaction}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid_clicker except: {error}")

    async def deeptrain_clicker(self, emotion_int) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            emotion_int = int(emotion_int)
            if emotion_int not in [1,2,3]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker ERROR: Wrong emotion_int: {emotion_int}")
                raise Exception(f'Wrong emotion_int: {emotion_int}')
            
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker emotion_int: {emotion_int}")
            # -------------------------------------------------------------------------- deeptrain
            web3_obj = Web3(Web3.HTTPProvider(WEB3_RPC))
            # 连接rpc节点
            connected = web3_obj.is_connected()
            if not connected:
                logger.error(f"Ooops! Failed to eth.is_connected.")
                raise Exception("Failed to eth.is_connected.")
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} white_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 情绪合约地址
            emotion_address = Web3.to_checksum_address(CONTRACT_EMOTION)
            if ERA3_ONLINE_STAMP > current_timestamp:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion)
            else:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion2)
        
            # 账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            # 情绪合约授权金额
            sender_allowance_usdc = usdc_contract.functions.allowance(sender_address, emotion_address).call()
            logger.debug(f"sender_allowance_usdc: {sender_allowance_usdc}") # 无穷大 115792089237316195423570985008687907853269984665640564039457584007913129.639935

            # 当期ID
            current_period_id = emotion_contract.functions.Issue().call()
            logger.debug(f"current_period_id: {current_period_id}")
            # 当前是否打卡
            current_emotion = emotion_contract.functions.IssueAddressEmotions(current_period_id, sender_address).call()
            logger.debug(f"current_emotion: {current_emotion}")

            if current_emotion > 0: # 
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker already completed | emotion: {current_emotion}")
                return 'Deeptrain already completed'

            # 当期信息
            current_period_info = emotion_contract.functions.IssueInformation(current_period_id).call()
            logger.debug(f"current_period_info: {current_period_info}")
            current_period_price = current_period_info[1]  # 当期单价
            logger.debug(f"current_period_price: {current_period_price}")
            end_timestamp = current_period_info[0]  # 当期结束时间戳
            logger.debug(f"end_timestamp: {end_timestamp}")
            # 时间已结束
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")
            if end_timestamp < current_timestamp:
                logger.info(f"The {current_period_id} period is over.")
                return f"The {current_period_id} period is over."

            # USDC余额不足
            if current_period_price > sender_balance_usdc:
                logger.error(f"Ooops! Insufficient USDC balance.")
                return "Insufficient USDC balance."
            
            # 情绪合约USDC授权额度不足
            if current_period_price > sender_allowance_usdc:
                logger.error(f"Ooops! Insufficient USDC authorization amount for emotion_contract.")
                # raise Exception("Insufficient USDC authorization amount for emotion_contract.")

                # 获取当前Gas
                latest_block = web3_obj.eth.get_block('latest')
                if latest_block is None:
                    logger.error(f"Ooops! Failed to eth.get_block.")
                    raise Exception("Failed to eth.get_block.")
                base_fee_per_gas = latest_block['baseFeePerGas']
                priority_fee_per_gas = web3_obj.eth.max_priority_fee  # 获取推荐的小费
                max_fee_per_gas = base_fee_per_gas + priority_fee_per_gas
                logger.info(f"base_fee_per_gas: {base_fee_per_gas} wei")
                logger.info(f"priority_fee_per_gas: {priority_fee_per_gas} wei")
                logger.info(f"max_fee_per_gas: {max_fee_per_gas} wei")

                # 构建交易 - 情绪合约金额授权
                transaction = usdc_contract.functions.approve(emotion_address, current_period_price).build_transaction(
                    {
                        "chainId": WEB3_CHAINID,
                        "from": sender_address,
                        "gas": 20000000,  # 最大 Gas 用量
                        "maxFeePerGas": max_fee_per_gas,  # 新的费用参数
                        "maxPriorityFeePerGas": priority_fee_per_gas,  # 新的费用参数
                        "nonce": web3_obj.eth.get_transaction_count(sender_address),
                    }
                )
                logger.debug(f"approve transaction: {transaction}")

                # 发送交易
                tx_success, _ = self.send_transaction_with_retry(web3_obj, transaction, max_fee_per_gas, priority_fee_per_gas)
                if tx_success == False:
                    logger.error(f"Ooops! Failed to send_transaction.")
                    raise Exception("Failed to send_transaction.")
                
                logger.success(f"The approve transaction was send successfully! - transaction: {transaction}")

            # 获取当前Gas
            latest_block = web3_obj.eth.get_block('latest')
            if latest_block is None:
                logger.error(f"Ooops! Failed to eth.get_block.")
                raise Exception("Failed to eth.get_block.")
            base_fee_per_gas = latest_block['baseFeePerGas']
            priority_fee_per_gas = web3_obj.eth.max_priority_fee  # 获取推荐的小费
            max_fee_per_gas = base_fee_per_gas + priority_fee_per_gas
            logger.info(f"base_fee_per_gas: {base_fee_per_gas} wei")
            logger.info(f"priority_fee_per_gas: {priority_fee_per_gas} wei")
            logger.info(f"max_fee_per_gas: {max_fee_per_gas} wei")

            # 构建交易 - 情绪打卡
            if ERA3_ONLINE_STAMP > current_timestamp:
                transaction = emotion_contract.functions.emotions( emotion_int ).build_transaction(
                    {
                        "chainId": WEB3_CHAINID,
                        "from": sender_address,
                        "gas": 20000000,  # 最大 Gas 用量
                        "maxFeePerGas": max_fee_per_gas,  # 新的费用参数
                        "maxPriorityFeePerGas": priority_fee_per_gas,  # 新的费用参数
                        "nonce": web3_obj.eth.get_transaction_count(sender_address),
                    }
                )
            else:
                transaction = emotion_contract.functions.emotions( sender_address, emotion_int ).build_transaction(
                    {
                        "chainId": WEB3_CHAINID,
                        "from": sender_address,
                        "gas": 20000000,  # 最大 Gas 用量
                        "maxFeePerGas": max_fee_per_gas,  # 新的费用参数
                        "maxPriorityFeePerGas": priority_fee_per_gas,  # 新的费用参数
                        "nonce": web3_obj.eth.get_transaction_count(sender_address),
                    }
                )
            logger.debug(f"emotions transaction: {transaction}")

            # 发送交易
            tx_success, _ = self.send_transaction_with_retry(web3_obj, transaction, max_fee_per_gas, priority_fee_per_gas)
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction.")
                raise Exception("Failed to send_transaction.")
            
            logger.success(f"The emotions transaction was send successfully! - transaction: {transaction}")
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker except: {error}")

    async def aicheckin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- aicheckin
            url = GAEA_API.rstrip('/')+'/api/ai/complete-mission'
            json_data = { }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker {response}")
                raise Exception(response)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin_clicker except: {error}")

    # --------------------------------------------------------------------------

    @helper
    async def daily_clicker_register(self):
        try:
            if len(self.client.userid) > 5:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} already registered")
                return "SUCCESS"
            
            # -------------------------------------------------------------------------- register
            clicker_response = await self.register_clicker()
            if clicker_response is None:
                return "ERROR"
            
            self.client.userid = clicker_response.get('uid', None)
            set_data_for_userid(self.client.runname, self.client.id, self.client.userid)

            clicker_response.pop('referral_link', None)
            clicker_response.pop('avatar', None)
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_register except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_login(self):
        try:
            if len(self.client.token) > 5:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} already login")
                return "SUCCESS"
            
            # -------------------------------------------------------------------------- login
            clicker_response = await self.login_clicker()
            if clicker_response is None:
                return "ERROR"
            
            self.client.token = clicker_response.get('token', None)
            set_data_for_token(self.client.runname, self.client.id, self.client.token)
            self.client.userid = clicker_response.get('user_info', None).get('uid', None)
            set_data_for_userid(self.client.runname, self.client.id, self.client.userid)

            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response['user_info']}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_login except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_session(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker()
            if clicker_response is None:
                return "ERROR"
            
            # logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} username: {clicker_response['name']} referral_code: {clicker_response['referral_code']} eth_address: {clicker_response['eth_address']} medal: {clicker_response['medal']} medal_expired: {((clicker_response['medal_expired']-int(time.time()))/60/60/24 if clicker_response['medal'] else 0):.2f} days")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_session except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_earninfo(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- earninfo
            clicker_response = await self.earninfo_clicker()
            if clicker_response is None:
                return "ERROR"
            
            # logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era_gaea: {clicker_response['era_gaea']} era_soul: {clicker_response['era_soul']} total_soul: {clicker_response['total_soul']} today_uptime: {(clicker_response['today_uptime']/60):.2f} hours")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_earninfo except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodinfo(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- godhoodinfo
            clicker_response = await self.godhoodinfo_clicker()
            if clicker_response is None:
                return "ERROR"
            
            # logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response['mood']}")
            if clicker_response['mood'] is None:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotion_code: None")
            else:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotion_code: {clicker_response['mood']['emotion_code']}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodinfo except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_era3info(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- era3_info
            clicker_response = await self.era3info_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3_info clicker_response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_era3info except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_openblindbox(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- blindbox_list
            clicker_response = await self.blindbox_list_clicker()
            cdkeys = clicker_response.get("cdkeys", [])
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- godhoodinfo
            clicker_response = await self.godhoodinfo_clicker()
            if clicker_response is None:
                return "ERROR"
            if clicker_response['mood'] is None:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: Please mint GODHOOD ID first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- blindbox_open
            clicker_response = await self.blindbox_open_clicker(cdkeys)
            if clicker_response is None:
                return "ERROR"
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_openblindbox except: {error}")
            return f"ERROR: {error}"
    
    @helper
    async def daily_clicker_referralreword(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- referral_list
            clicker_response = await self.referral_list_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- referral_complete
            referrallist = clicker_response.get("list", [])
            idx=0
            for item in referrallist:
                status = item.get("status", 0)
                if status == 1:
                    # -------------------------------------------------------------------------- referral_complete
                    clicker_response = await self.referral_complete_clicker()
                    if clicker_response is None:
                        return "ERROR"
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")

                    idx+=1
                    delay = random.randint(1, 5)
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete delay: {delay} seconds")
                    await asyncio.sleep(delay)
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete count: {idx}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_referralreword except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_bindaddress(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker()
            if clicker_response is None:
                return "ERROR"
            
            # logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} eth_address: {clicker_response['eth_address']} ")
            if clicker_response['eth_address'] is not None and clicker_response['eth_address'] != "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The address has been bound")
                return "SUCCESS"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- bindaddress
            clicker_response = await self.bind_address_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_referralreword except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_checkin(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- 1 checkin
            clicker_response = await self.checkin_clicker()
            if clicker_response is None:
                return "ERROR"
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_checkin except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_signin(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- 2 signin
            clicker_response = await self.signin_clicker()
            if clicker_response is None:
                return "ERROR"
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_signin except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_dailycheckin(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- dailylist
            clicker_response = await self.dailylist_clicker()
            if clicker_response is None:
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            if clicker_response['today'] == 1:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Daily rewards completed")
                return "SUCCESS"
            else:
                # --------------------------------------------------------------------------
                dailylist = clicker_response.get("list", [])
                daily = 0
                for item in dailylist:
                    reward = item.get("reward", "")
                    if len(reward) > 0:
                        continue
                    daily = item.get("daily", 0)
                    break
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily: {daily}")
                
                # -------------------------------------------------------------------------- 1 dailycheckin
                clicker_response = await self.dailycheckin_clicker(daily)
                if clicker_response is None:
                    return "ERROR"
                
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_dailycheckin except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_medalcheckin(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker()
            if clicker_response is None:
                return "ERROR"
            
            # logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medal: {clicker_response['medal']} medal_expired: {((clicker_response['medal_expired']-int(time.time()))/60/60/24 if clicker_response['medal'] else 0):.2f} days")

            # --------------------------------------------------------------------------
            if clicker_response['medal']:
                # -------------------------------------------------------------------------- 2 medalcheckin
                clicker_response = await self.medalcheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_medalcheckin except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_aitrain(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            if len(clicker_response['today']) > 0:
                emotion = clicker_response['today'].split('_')[0]
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Training already completed")
                # return "SUCCESS"
            else:
                # -------------------------------------------------------------------------- godhoodinfo
                clicker_response = await self.godhoodinfo_clicker()
                if clicker_response is None:
                    return "ERROR"
                is_godhood_id = "0"
                if clicker_response['mood']:
                    is_godhood_id = "1"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 3 aitrain
                emotion=os.environ.get('CHOOSE_EMOTION', '0')
                if emotion == '0':
                    emotion = random.choice(["1", "2", "3"])
                emotion_detail=emotion+'_1_'+is_godhood_id
                clicker_response = await self.aitrain_clicker(emotion_detail)
                if clicker_response is None:
                    return "ERROR"
                
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodid(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- 5 godhoodid
            await self.godhoodid_clicker()

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodid except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodemotion(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- godhoodemotion
            clicker_response = await self.godhoodemotion_clicker()
            if clicker_response is None:
                return "ERROR"
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodinfo except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_deeptrain(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            
            if len(clicker_response['today']) > 0:
                emotion = clicker_response['today'].split('_')[0]
            else:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please complete the aitraining first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- 5 deeptrain
            await self.deeptrain_clicker(emotion)

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_deeptrain except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_aicheckin(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            today = time.strftime("%d/%m/%Y", time.localtime())
            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            
            if len(clicker_response['today']) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please complete the aitraining first")
                return "ERROR"
            
            ailist = clicker_response['cycle']
            if ailist == []:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please complete the deeptraining first")
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist: {ailist}")
            today_complete = 0
            for item in ailist:
                if item['date'] == today:
                    today_complete = 1 if item['status'] == 2 else 0
            if today_complete:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Checkin already completed")
                # return "SUCCESS"
            else:
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 4 aicheckin
                clicker_response = await self.aicheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aicheckin except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_alltask(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # # -------------------------------------------------------------------------- 1 checkin
            # await self.checkin_clicker()

            # delay = random.randint(10, 20)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 1 checkin_clicker delay: {delay} seconds")
            # await asyncio.sleep(delay)

            # # -------------------------------------------------------------------------- 2 signin
            # await self.signin_clicker()

            # delay = random.randint(10, 20)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 2 signin_clicker delay: {delay} seconds")
            # await asyncio.sleep(delay)

            # -------------------------------------------------------------------------- dailylist
            clicker_response = await self.dailylist_clicker()
            if clicker_response is None:
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # --------------------------------------------------------------------------
            if clicker_response['today'] == 1:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Daily rewards completed")
                # return "SUCCESS"
            else:
                dailylist = clicker_response.get("list", [])
                daily = 0
                for item in dailylist:
                    reward = item.get("reward", "")
                    if len(reward) > 0:
                        continue
                    daily = item.get("daily", 0)
                    break
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily: {daily}")
                
                # -------------------------------------------------------------------------- 1 dailycheckin
                await self.dailycheckin_clicker(daily)

                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 1 dailycheckin_clicker delay: {delay} seconds")
                await asyncio.sleep(delay)


            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker()
            if clicker_response is None:
                return "ERROR"
            
            # logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medal: {clicker_response['medal']} medal_expired: {((clicker_response['medal_expired']-int(time.time()))/60/60/24 if clicker_response['medal'] else 0):.2f} days")
            delay = random.randint(10, 20)
            await asyncio.sleep(delay)

            if clicker_response['medal']:
                # -------------------------------------------------------------------------- 2 medalcheckin
                clicker_response = await self.medalcheckin_clicker()
                if clicker_response is None:
                    return "ERROR"

                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 2 dailycheckin_clicker delay: {delay} seconds")
                await asyncio.sleep(delay)


            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            if len(clicker_response['today']) > 0:
                emotion = clicker_response['today'].split('_')[0]
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Training already completed")
                # return "SUCCESS"
            else:
                # -------------------------------------------------------------------------- godhoodinfo
                clicker_response = await self.godhoodinfo_clicker()
                if clicker_response is None:
                    return "ERROR"
                is_godhood_id = "1" if clicker_response['mood'] else "0"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 3 aitrain
                emotion=os.environ.get('CHOOSE_EMOTION', '0')
                if emotion == '0':
                    emotion = random.choice(["1", "2", "3"])
                emotion_detail=emotion+'_1_'+is_godhood_id
                clicker_response = await self.aitrain_clicker(emotion_detail)
                if clicker_response is None:
                    return "ERROR"

                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 3 aitrain_clicker delay: {delay} seconds")
                await asyncio.sleep(delay)


            # --------------------------------------------------------------------------
            if len(self.client.prikey) in [64,66]:
                # -------------------------------------------------------------------------- 4 deeptrain
                await self.deeptrain_clicker(emotion)

                delay = random.randint(60, 90)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 4 deeptrain_clicker delay: {delay} seconds")
                await asyncio.sleep(delay)


            today = time.strftime("%d/%m/%Y", time.localtime())
            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            
            if len(clicker_response['today']) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please complete the aitraining first")
                return "ERROR"
            
            ailist = clicker_response['cycle']
            if ailist == []:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please complete the deeptraining first")
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist: {ailist}")
            today_complete = 0
            for item in ailist:
                if item['date'] == today:
                    today_complete = 1 if item['status'] == 2 else 0
            if today_complete:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Checkin already completed")
                # return "SUCCESS"
            else:
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain delay: {delay} seconds")
                await asyncio.sleep(delay)
                
                # -------------------------------------------------------------------------- 5 aicheckin
                clicker_response = await self.aicheckin_clicker()
                if clicker_response is None:
                    return "ERROR"

                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aicheckin except: {error}")
            return f"ERROR: {error}"
