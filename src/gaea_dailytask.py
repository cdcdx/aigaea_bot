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

from utils.services import get_captcha_key
from utils.decorators import helper
from src.gaea_client import GaeaClient
from config import get_envsion, set_envsion, GAEA_API, WEB3_RPC, WEB3_CHAINID, CONTRACT_USDC, CONTRACT_EMOTION
from utils.helpers import get_data_for_token, set_data_for_token


# ABI
contract_abi_usdc = [
    {
        "inputs": [
            { "internalType": "address", "name": "account", "type": "address" }
        ],
        "name": "balanceOf",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ], 
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "owner", "type": "address" },
            { "internalType": "address", "name": "spender", "type": "address" }
        ],
        "name": "allowance",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "address", "name": "spender", "type": "address" }, 
            { "internalType": "uint256", "name": "amount", "type": "uint256" }
        ],
        "name": "approve",
        "outputs": [
            { "internalType": "bool", "name": "", "type": "bool" }
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    },
]
contract_abi_emotion = [
    {
        "inputs": [
            { "internalType": "uint8", "name": "_num", "type": "uint8" }
        ],
        "name": "emotions",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "Issue",
        "outputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" }
        ],
        "name": "IssueInformation",
        "outputs": [
            { "internalType": "uint256", "name": "duration", "type": "uint256" },
            { "internalType": "uint256", "name": "price", "type": "uint256" },
            { "internalType": "uint256", "name": "putmoney", "type": "uint256" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            { "internalType": "uint256", "name": "", "type": "uint256" },
            { "internalType": "address", "name": "", "type": "address" }
        ],
        "name": "IssueAddressEmotions",
        "outputs": [
            { "internalType": "uint8", "name": "", "type": "uint8" }
        ],
        "stateMutability": "view",
        "type": "function"
    },
]


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

    async def login_clicker(self) -> None:
        try:
            headers = self.getheaders()
            headers.pop('Authorization', None)

            # -------------------------------------------------------------------------- captcha
            capcha_key=''
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
                    logger.error(f"id: {self.client.id} get_captcha_key retry:{int(total_time/30)} except ERROR: {str(error).splitlines()[0]} ")
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
            url=GAEA_API+'/api/auth/login'
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
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker response: {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {message}")
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker except: {error}")
            raise Exception(error)

    async def checkin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                headers = self.getheaders()
                set_data_for_token('', self.client.id, self.client.token)
            # -------------------------------------------------------------------------- checkin
            url=GAEA_API+'/api/mission/complete-mission'
            json_data = {
                "mission_id": "1"
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin response: {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin => {response['data']}")
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin => {message}")
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin except: {error}")
            raise Exception(error)

    async def signin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                headers = self.getheaders()
                set_data_for_token('', self.client.id, self.client.token)
            # -------------------------------------------------------------------------- signin
            url=GAEA_API+'/api/signin/complete'
            json_data = {
                "detail": "Positive_Love"
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin response: {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin => {response['data']}")
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin => {message}")
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin except: {error}")
            raise Exception(error)

    async def aitrain_clicker(self, emotion_detail) -> None:
        try:
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain emotion_detail: {emotion_detail}")

            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                headers = self.getheaders()
                set_data_for_token('', self.client.id, self.client.token)
            # -------------------------------------------------------------------------- aitrain
            url=GAEA_API+'/api/ai/complete'
            json_data = {
                "detail": emotion_detail
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain response: {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain => {response['data']}")
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain => {message}")
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain except: {error}")
            raise Exception(error)

    async def aicheckin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                headers = self.getheaders()
                set_data_for_token('', self.client.id, self.client.token)
            # -------------------------------------------------------------------------- aicheckin
            url=GAEA_API+'/api/ai/complete-mission'
            json_data = { }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin response: {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin => {response['data']}")
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin => {message}")
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aicheckin except: {error}")
            raise Exception(error)

    async def deeptrain_clicker(self, emotion) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain ERROR: prikey length must be 64 or 66")
                raise Exception(f"prikey length must be 64 or 66")
            
            emotion = int(emotion)
            if emotion not in [1,2,3]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain ERROR: Wrong emotion: {emotion}")
                raise Exception(f'Wrong emotion: {emotion}')
            
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain emotion: {emotion}")
            # -------------------------------------------------------------------------- deeptrain
            web3_obj = Web3(Web3.HTTPProvider(WEB3_RPC))
            # 连接rpc节点
            connected = web3_obj.is_connected()
            if not connected:
                logger.error(f"Ooops! Failed to eth.is_connected.")
                raise Exception("Failed to eth.is_connected.")
            
            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} white_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 情绪合约地址
            emotion_address = Web3.to_checksum_address(CONTRACT_EMOTION)
            emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion)
        
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
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain already completed | emotion: {current_emotion}")
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
            transaction = emotion_contract.functions.emotions( emotion ).build_transaction(
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
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain except: {error}")
            raise Exception(error)

    @helper
    async def daily_clicker_checkin(self):
        try:
            # -------------------------------------------------------------------------- 1 checkin
            await self.checkin_clicker()

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 1 checkin delay: {delay} seconds")
            await asyncio.sleep(delay)

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_checkin except: {error}")
            return f"ERROR: {error}"
            raise Exception(error)

    @helper
    async def daily_clicker_signin(self):
        try:
            # -------------------------------------------------------------------------- 2 signin
            await self.signin_clicker()

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 2 signin delay: {delay} seconds")
            await asyncio.sleep(delay)

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_signin except: {error}")
            return f"ERROR: {error}"
            raise Exception(error)

    @helper
    async def daily_clicker_aitrain(self):
        try:
            # -------------------------------------------------------------------------- 3 aitrain
            emotion=os.environ.get('CHOOSE_EMOTION', '3')
            emotion_detail=emotion+'_1_1'
            await self.aitrain_clicker(emotion_detail)

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 3 aitrain delay: {delay} seconds")
            await asyncio.sleep(delay)

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain except: {error}")
            return f"ERROR: {error}"
            raise Exception(error)

    @helper
    async def daily_clicker_aicheckin(self):
        try:
            # -------------------------------------------------------------------------- 4 aicheckin
            await self.aicheckin_clicker()

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 4 aicheckin delay: {delay} seconds")
            await asyncio.sleep(delay)

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aicheckin except: {error}")
            return f"ERROR: {error}"
            raise Exception(error)

    @helper
    async def daily_clicker_deeptrain(self):
        try:
            # -------------------------------------------------------------------------- 5 deeptrain
            emotion=os.environ.get('CHOOSE_EMOTION', '3')
            await self.deeptrain_clicker(emotion)

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 5 deeptrain delay: {delay} seconds")
            await asyncio.sleep(delay)

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_deeptrain except: {error}")
            return f"ERROR: {error}"
            raise Exception(error)

    @helper
    async def daily_clicker_alltask(self):
        try:
            # -------------------------------------------------------------------------- 1 checkin
            await self.checkin_clicker()

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 1 checkin delay: {delay} seconds")
            await asyncio.sleep(delay)

            # -------------------------------------------------------------------------- 2 signin
            await self.signin_clicker()

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 2 signin delay: {delay} seconds")
            await asyncio.sleep(delay)

            # -------------------------------------------------------------------------- 3 aitrain
            emotion=os.environ.get('CHOOSE_EMOTION', '3')
            emotion_detail=emotion+'_1_1'
            await self.aitrain_clicker(emotion_detail)

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 3 aitrain delay: {delay} seconds")
            await asyncio.sleep(delay)

            # -------------------------------------------------------------------------- 4 aicheckin
            await self.aicheckin_clicker()

            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 4 aicheckin delay: {delay} seconds")
            await asyncio.sleep(delay)

            # --------------------------------------------------------------------------

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aicheckin except: {error}")
            return f"ERROR: {error}"
            raise Exception(error)
