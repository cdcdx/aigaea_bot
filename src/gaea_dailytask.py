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
from utils.contract_abi import contract_abi_usdc, contract_abi_emotion, contract_abi_emotion2, contract_abi_emotion3, contract_abi_reward, contract_abi_reward3, contract_abi_invite, contract_abi_mint, contract_abi_choice, contract_abi_award, contract_abi_ticket
from utils.decorators import helper
from utils.helpers import get_data_for_token, set_data_for_token, set_data_for_userid, get_emotion_for_txt, get_choice_for_txt
from utils.services import get_captcha_key, generate_random_groups
from config import get_envsion, set_envsion, GAEA_API, ERA3_ONLINE_STAMP, EMOTION3_ONLINE_STAMP, SNAIL_UNIT
from config import WEB3_RPC, WEB3_RPC_FIXED, WEB3_CHAINID, CONTRACT_USDC, CONTRACT_SXP, CONTRACT_TICKET, CONTRACT_INVITE, CONTRACT_EMOTION, CONTRACT_CHOICE, CONTRACT_REWARD, CONTRACT_AWARD, CONTRACT_SNFTMINT, CONTRACT_ANFTMINT, CAPTCHA_KEY, REFERRAL_CODE, REFERRAL_ADDRESS, POOLING_ADDRESS

def connect_web3_rpc():
    """
    连接Web3 RPC节点
    
    Returns:
        Web3: 已连接的Web3实例
        
    Raises:
        Exception: 当无法连接到任何RPC节点时抛出异常
    """
    web3_obj = Web3(Web3.HTTPProvider(WEB3_RPC))
    # 连接rpc节点
    if not web3_obj.is_connected():
        logger.debug(f"Unable to connect to the network: {WEB3_RPC}")
        web3_obj = Web3(Web3.HTTPProvider(WEB3_RPC_FIXED))
        if not web3_obj.is_connected():
            logger.error(f"Unable to connect to the network: {WEB3_RPC_FIXED}")
            raise Exception("Failed to eth.is_connected.")
    return web3_obj

class TransactionHelper:
    """
    以太坊交易辅助类，提供交易构建、发送和重试机制
    """
    
    def __init__(self, web3_obj, max_base_fee_gwei=20, max_priority_fee_gwei=2, default_gas_limit=200000):
        self.web3_obj = web3_obj
        self.max_base_fee = web3_obj.to_wei(max_base_fee_gwei, 'gwei')
        self.max_priority_fee = web3_obj.to_wei(max_priority_fee_gwei, 'gwei')
        self.default_gas_limit = default_gas_limit
        self.gas_increase_factor = 1.3

    def build_base_transaction(self, sender_address, config_chainid):
        """
        构建基础交易参数
        """
        latest_block = self.web3_obj.eth.get_block('latest')
        base_fee = latest_block['baseFeePerGas']
        priority_fee = self.web3_obj.eth.max_priority_fee
        priority_fee = int(priority_fee * 1.5)  # 增加50%的缓冲
        max_fee = int(base_fee * 1.5) + priority_fee   # 增加50%的缓冲
        
        # 确保 max_fee >= priority_fee
        max_fee = max(max_fee, priority_fee)
        
        logger.debug(f"baseFeePerGas: {base_fee} wei")
        logger.debug(f"maxPriorityFeePerGas: {priority_fee} wei")
        logger.debug(f"maxFeePerGas: {max_fee} wei")
        
        return {
            "chainId": config_chainid,
            "from": sender_address,
            "nonce": self.web3_obj.eth.get_transaction_count(sender_address, 'pending'),
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": priority_fee,
        }

    def decode_revert_reason(self, hex_error):
        """
        解析 Solidity 合约的 revert 错误信息
        
        Args:
            hex_error: 16进制错误信息
            
        Returns:
            str: 解码后的错误信息
        """
        try:
            # 移除 '0x' 前缀
            if hex_error.startswith('0x'):
                hex_error = hex_error[2:]
            # 检查是否是标准的 Error(string) 选择器
            if hex_error.startswith('08c379a0'):
                # 跳过选择器 (4 bytes = 8 hex chars)
                data = hex_error[8:]
                
                # 获取字符串长度 (offset 32 bytes = 64 hex chars)
                length_hex = data[64:128]
                length = int(length_hex, 16)
                
                # 获取实际的错误消息 (从 128 hex chars 开始)
                message_hex = data[128:128 + length*2]
                message = bytes.fromhex(message_hex).decode('utf-8')
                
                return message
            else:
                return hex_error
        except Exception as e:
            return f"Unable to resolve: {str(e)}"

    def _adjust_gas_by_error_type(self, attempt, max_retries, gas_limit, error_str):
        """
        根据错误类型调整gas策略
        """
        if attempt == 0:
            # 第一次尝试失败时使用默认gas值
            return self.default_gas_limit
        elif "intrinsic gas too low" in error_str or "out of gas" in error_str:
            # 如果是gas不足相关错误，增加gas限制
            return int(gas_limit * self.gas_increase_factor)
        elif "replacement transaction underpriced" in error_str:
            # 如果是费用不足，增加费用但保持gas不变
            return min(int(gas_limit * 1.15), self.default_gas_limit*2)
        elif "nonce too low" in error_str:
            # nonce错误时保持gas不变
            return gas_limit
        elif attempt < max_retries - 1:
            # 其他错误情况下适度增加gas并继续尝试
            return int(gas_limit * 1.25)
        else:
            # 最后一次尝试仍然失败则返回原值
            return gas_limit

    def send_transaction_with_retry(self, transaction, web3_prikey, max_retries=3, retry_interval=3):
        """
        发送以太坊交易，带重试机制
        
        Args:
            transaction: 交易对象
            web3_prikey: 私钥
            max_retries: 最大重试次数
            retry_interval: 重试间隔时间
        """
        # 为避免在循环中重复定义，将一些变量在循环外定义
        attempt = 0
        initial_base_fee = None
        initial_priority_fee = None
        tx_bytes = None
        
        while attempt < max_retries:
            try:
                logger.debug(f"transaction: {transaction}")
                
                # 动态更新 Gas 参数
                latest_block = self.web3_obj.eth.get_block('latest')
                base_fee = latest_block['baseFeePerGas']
                current_priority_fee = self.web3_obj.eth.max_priority_fee
                
                # 记录初始费用用于比较
                if attempt == 0:
                    initial_base_fee = base_fee
                    initial_priority_fee = current_priority_fee
                
                # 根据尝试次数调整费用
                if attempt > 0:
                    # 费用增长策略: 每次尝试增加15%费用，但不超过上限
                    fee_multiplier = 1.15 ** attempt
                    priority_fee = min(
                        int(initial_priority_fee * fee_multiplier), 
                        self.max_priority_fee
                    )
                    # 更新nonce
                    transaction['nonce'] = self.web3_obj.eth.get_transaction_count(transaction['from'], 'pending')
                else:
                    # 初始交易使用保守的费用
                    priority_fee = min(int(current_priority_fee * 1.1), self.max_priority_fee)
                    
                # 计算最大费用
                max_fee = min(
                    int(base_fee * 1.1) + priority_fee,
                    self.max_base_fee
                )
                
                # 确保 max_fee >= priority_fee
                max_fee = max(max_fee, priority_fee)
                
                # 更新交易参数
                transaction.update({
                    "maxFeePerGas": max_fee,
                    "maxPriorityFeePerGas": priority_fee,
                })
                logger.debug(f"update transaction fees: maxFee={max_fee}, priorityFee={priority_fee}")
                
                # 估算 Gas
                gas_limit = self.default_gas_limit  # 默认值
                try:
                    estimated_gas = self.web3_obj.eth.estimate_gas(transaction)
                    # 增加合理的gas限制缓冲，随着重试次数增加而增加
                    buffer_multiplier = min(1.0 + (0.1 * attempt), self.gas_increase_factor)  # 最多1.3倍缓冲
                    gas_limit = int(estimated_gas * buffer_multiplier)
                    if gas_limit < 100000:
                        gas_limit = 100000
                except Exception as e:
                    logger.error(f"Failed to eth.estimate_gas: {str(e)}")
                    decoded_error = self.decode_revert_reason(str(e)) if '0x' in str(e) else str(e)
                    
                    # 根据错误类型调整gas策略
                    error_str = str(e).lower()
                    gas_limit = self._adjust_gas_by_error_type(attempt, max_retries, gas_limit, error_str)
                    
                    if attempt >= max_retries - 1:
                        # 最后一次尝试仍然失败则返回错误
                        return False, {"tx_hash": "eth.estimate_gas", "msg": decoded_error}
                    else:
                        logger.warning(f"Adjusting gas limit to: {gas_limit}")
                
                logger.debug(f"gas_limit: {gas_limit}")
                transaction["gas"] = gas_limit
                logger.debug(f"update transaction with gas: {transaction}")
                
                # 使用私钥签名交易
                signed_transaction = self.web3_obj.eth.account.sign_transaction(transaction, web3_prikey)
                logger.debug(f"signed_transaction: {signed_transaction}")

                # 发送交易
                tx_hash = self.web3_obj.eth.send_raw_transaction(signed_transaction.raw_transaction)
                logger.debug(f"Transaction sent - tx_hash: {tx_hash.hex()}")
                tx_bytes = f"0x{tx_hash.hex()}"
                
                # 等待交易完成
                try:
                    receipt_timeout = 30 if attempt == 0 else 15
                    receipt = self.web3_obj.eth.wait_for_transaction_receipt(tx_hash, timeout=receipt_timeout)
                except Exception as e:
                    logger.error(f"Transaction not included in chain after {receipt_timeout} seconds: {str(e)}")
                    return False, {"tx_hash": tx_bytes, "msg": f"Transaction not included in chain after {receipt_timeout} seconds"}
                
                logger.debug(f"Waiting to complete - receipt: {receipt}")
                tx_bytes = f"0x{tx_hash.hex()}"
                    
                if receipt['status'] == 1:
                    logger.success(f"Transaction successful - tx_hash: {tx_bytes}")
                    return True, {"tx_hash": tx_bytes}
                else:
                    logger.error(f"Transaction failed - tx_hash: {tx_bytes}")
                    return False, {"tx_hash": tx_bytes}
                
            except ValueError as e:
                logger.warning(f"Failed to transaction ValueError ETH : {str(e)}")
                # 处理ValueError异常
                try:
                    error_message = e.args[0].get('message', '') if isinstance(e.args[0], dict) else str(e)
                    error_code = e.args[0].get('code', None) if isinstance(e.args[0], dict) else None
                    
                    if 'rpc error' in error_message.lower() or 'node error' in error_message.lower():
                        logger.error(f"RPC node error encountered: {error_message}")
                        # 返回更明确的错误信息，指示这是RPC节点错误
                        result = False, {"tx_hash": tx_bytes, "msg": f"RPC node error: {error_message}. Please check node connectivity and logs for more information."}
                    elif 'intrinsic gas too low' in error_message.lower():
                        # 如果是gas过低错误，在下次尝试时增加gas
                        gas_limit = int(gas_limit * self.gas_increase_factor)
                        result = False, {"tx_hash": tx_bytes, "msg": error_message}
                    elif 'replacement transaction underpriced' in error_message.lower():
                        # 费用不足错误，下次尝试时增加费用
                        result = False, {"tx_hash": tx_bytes, "msg": error_message}
                    elif 'nonce too low' in error_message.lower():
                        # nonce错误，更新nonce
                        transaction['nonce'] = self.web3_obj.eth.get_transaction_count(transaction['from'], 'pending')
                        result = False, {"tx_hash": tx_bytes, "msg": error_message}
                    else:
                        result = False, {"tx_hash": tx_bytes, "msg": error_message, "code": error_code}
                except Exception as e:
                    result = False, {"tx_hash": tx_bytes, "msg": str(e)}
                return result
            
            except Exception as e:
                error_msg = str(e).lower()
                if "replacement transaction underpriced" in error_msg:
                    logger.warning(f"Priority fee insufficient, will increase... (Try {attempt+1}/{max_retries})")
                    if attempt + 1 >= max_retries:
                        logger.error(f"Maximum number of retries: {error_msg}")
                        return False, {"tx_hash": "", "msg": f"Maximum number of retries: {error_msg}"}
                elif "max fee per gas" in error_msg:
                    logger.warning(f"Basic fee insufficient, will increase... (Try {attempt+1}/{max_retries})")
                elif "nonce too low" in error_msg:
                    logger.warning(f"Nonce is too low, get the latest nonce... (Try {attempt+1}/{max_retries})")
                    transaction['nonce'] = self.web3_obj.eth.get_transaction_count(transaction['from'], 'pending')
                elif "already known" in error_msg:
                    logger.warning(f"Awaiting confirmation... (Try {attempt+1}/{max_retries})")
                    # 交易已经在内存池中，我们应该查询它的状态而不是简单等待
                    try:
                        # 尝试通过交易哈希获取交易详情
                        pending_tx = self.web3_obj.eth.get_transaction(signed_transaction.hash)
                        if pending_tx:
                            logger.info(f"Found pending transaction: {signed_transaction.hash.hex()}")
                            # 等待交易确认
                            try:
                                receipt = self.web3_obj.eth.wait_for_transaction_receipt(signed_transaction.hash, timeout=30)
                                if receipt['status'] == 1:
                                    logger.success(f"Transaction successful - tx_hash: {signed_transaction.hash.hex()}")
                                    return True, {"tx_hash": signed_transaction.hash.hex()}
                                else:
                                    logger.error(f"Transaction failed - tx_hash: {signed_transaction.hash.hex()}")
                                    return False, {"tx_hash": signed_transaction.hash.hex()}
                            except Exception as wait_e:
                                logger.error(f"Pending transaction timeout: {str(wait_e)}")
                    except Exception as fetch_e:
                        logger.warning(f"Unable to retrieve pending transactions: {str(fetch_e)}")
                    
                    # 交易已经在内存池中，等待确认
                    time.sleep(retry_interval)
                    attempt += 1
                    continue
                else:
                    logger.error(f"Failed to send transaction: {e} (Try {attempt+1}/{max_retries})")
                
                attempt += 1
                if attempt < max_retries:
                    logger.debug(f"Retrying in {retry_interval} seconds...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Max retries reached. Failed to eth.send_raw_transaction: {str(e)}")
                    return False, {"tx_hash": "send_raw_transaction", "msg": str(e)}

class GaeaDailyTask:
    # 类变量用于存储全局的web3实例
    _shared_web3_instance = None

    def __init__(self, client: GaeaClient) -> None:
        self.client = client
        # 使用类变量，确保只连接一次
        if GaeaDailyTask._shared_web3_instance is None:
            GaeaDailyTask._shared_web3_instance = connect_web3_rpc()
        self._web3_instance = GaeaDailyTask._shared_web3_instance

    # 如果需要在实例方法中确保连接可用，可以添加检查
    def ensure_web3_connection(self):
        """确保web3连接仍然可用"""
        if self._web3_instance is None or not self._web3_instance.is_connected():
            self._web3_instance = connect_web3_rpc()
        return self._web3_instance

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

    # -------------------------------------------------------------------------- web3

    # build base transaction
    def build_base_transaction(self, web3_obj, sender_address, config_chainid):
        """
        构建基础交易参数
        """
        tx_helper = TransactionHelper(web3_obj)
        return tx_helper.build_base_transaction(sender_address, config_chainid)

    # send transaction
    def send_transaction_with_retry(self, web3_obj, transaction, web3_prikey, max_retries=3, retry_interval=3):
        """
        发送以太坊交易，带重试机制
        
        Args:
            web3_obj: Web3实例
            transaction: 交易对象
            web3_prikey: 私钥
            max_retries: 最大重试次数
            retry_interval: 重试间隔时间
        """
        tx_helper = TransactionHelper(web3_obj)
        return tx_helper.send_transaction_with_retry(transaction, web3_prikey, max_retries, retry_interval)

    # revert reason
    def decode_revert_reason(self, hex_error):
        """
        解析 Solidity 合约的 revert 错误信息
        
        Args:
            hex_error: 16进制错误信息
        Returns:
            str: 解码后的错误信息
        """
        tx_helper = TransactionHelper(self._web3_instance)
        return tx_helper.decode_revert_reason(hex_error)

    # -------------------------------------------------------------------------- 接口

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker {response}")

            code = response.get('code', None)
            if code not in [200, 201]:
                username = self.client.email
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- register
            url = GAEA_API.rstrip('/')+'/api/auth/register'
            json_data = {
                "email": self.client.email,
                "username": username,
                "password": self.client.passwd,
                "referral_code": random.choice(REFERRAL_CODE),
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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session_clicker {response}")

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
            
            # 钱包地址
            sender_address = Web3().eth.account.from_key(self.client.prikey).address
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bind_address_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo_clicker {response}")

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

    async def godhoodgrowthinfo_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- godhoodgrowthinfo
            url = GAEA_API.rstrip('/')+'/api/godhood/growth/info'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo_clicker except: {error}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3info_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                datas = response['data']
                total = response['total']
                datas_len = len(datas)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list_clicker datas: {datas} datas_len: {datas_len} total: {total}")
                cdkeys = []
                if total > 0:
                    for i in range(datas_len):
                        cdkeys.append(datas[i]['cdkey'])
                return {'cdkeys': cdkeys, 'total': total}
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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open_clicker {response}")

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

    async def ticketbox_list_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- ticketbox_list
            url = GAEA_API.rstrip('/')+'/api/ticket/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                datas = response['data']
                if len(datas) == 0:
                    logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list_clicker ERROR: No ticket")
                    return None
                total = response['total']
                cdkeys = []
                if total >= 10:
                    for i in range(10):
                        cdkeys.append(datas[i]['cdkey'])
                else:
                    for i in range(total):
                        cdkeys.append(datas[i]['cdkey'])
                return {'cdkeys': cdkeys}
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list_clicker except: {error}")

    # -------------------------------------------------------------------------- 日常任务

    ## 日常签到
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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin_clicker => {response['data']}")
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

    ## 勋章签到
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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin_clicker => {response['data']}")
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

    ## 训练签到
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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain_clicker => {response['data']}")
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

    async def traincheckin_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- traincheckin
            url = GAEA_API.rstrip('/')+'/api/ai/complete-mission'
            json_data = { }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin_clicker except: {error}")

    ## 训练抉择信息
    async def emotionperiod_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- emotionperiod
            url = GAEA_API.rstrip('/')+'/api/emotion/period'
            json_data = {
                "chain_id": 8453
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod_clicker url: {url}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod_clicker except: {error}")

    async def choiceperiod_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- choiceperiod
            url = GAEA_API.rstrip('/')+'/api/choice/period'
            json_data = {
                "chain_id": 8453
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod_clicker url: {url}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod_clicker except: {error}")

    # -------------------------------------------------------------------------- 任务
    
    ## 任务列表
    async def missionlist_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- missionlist
            url = GAEA_API.rstrip('/')+'/api/mission/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist_clicker except: {error}")

    async def missionconnect_clicker(self, mission_id) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- missionconnect
            if 10 < int(mission_id) < 99:
                url = GAEA_API.rstrip('/')+'/api/auth/retweet/connect?id='+str(mission_id)
            elif 110 < int(mission_id) < 199:
                url = GAEA_API.rstrip('/')+'/api/auth/partner/connect?id='+str(mission_id)
            else:
                return None
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect_clicker except: {error}")

    async def missioncomplete_clicker(self, mission_id) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- missioncomplete
            url = GAEA_API.rstrip('/')+'/api/mission/complete-mission'
            json_data = {
                "mission_id": f"{mission_id}"
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete_clicker except: {error}")

    ## 里程碑任务
    async def milestonelist_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- milestonelist
            url = GAEA_API.rstrip('/')+'/api/milestone/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist_clicker except: {error}")

    async def milestoneburn_clicker(self, milestoneid, burn_tickets) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- milestoneburn
            url = GAEA_API.rstrip('/')+'/api/milestone/burn'
            json_data = {
                "burn": burn_tickets
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn_clicker except: {error}")

    async def milestoneclaim_clicker(self, milestoneid, taskid) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- milestoneclaim
            url = GAEA_API.rstrip('/')+f'/api/milestone/claim/{milestoneid}/{taskid}'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim_clicker except: {error}")

    ## 视听任务
    async def visionlist_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- visionlist
            url = GAEA_API.rstrip('/')+'/api/vision/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist_clicker except: {error}")

    async def visionburn_clicker(self, visionid, burn_tickets) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- visionburn
            chat_datas = generate_random_groups()
            
            url = GAEA_API.rstrip('/')+'/api/vision/chat'
            json_data = {
                "id": visionid,
                "ticket": burn_tickets,
                "datas": chat_datas
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn_clicker url: {url}")
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201, 206]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['msg']}")
                return response['msg']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('content_type', None)}" 
                if message.find('plain') > 0:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn_clicker => {message}")
                    return 'SUCCESS'
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn_clicker except: {error}")

    async def visionclaim_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- visionclaim
            url = GAEA_API.rstrip('/')+f'/api/vision/claimed'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim_clicker except: {error}")

    # -------------------------------------------------------------------------- 上链
    
    ## 买神格卡
    async def godhoodid_buy_clicker(self) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid_buy_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            # -------------------------------------------------------------------------- godhoodid
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            if sender_balance_eth == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 账户余额为0")
                return "ERRRO"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            
            # 购卡合约地址
            invite_address = Web3.to_checksum_address(CONTRACT_INVITE)
            invite_contract = web3_obj.eth.contract(address=invite_address, abi=contract_abi_invite)

            # 当前是否购卡
            is_godhoodid = invite_contract.functions.isgodhoodID( sender_address ).call()
            logger.debug(f"is_godhoodid: {is_godhoodid}")

            if is_godhoodid: # 
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} GodhoodID already completed | godhoodid: {is_godhoodid}")
                return 'GodhoodID already completed'

            # --------------------------------------------------------------------------

            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            # 购卡合约授权金额
            sender_allowance_usdc = usdc_contract.functions.allowance(sender_address, invite_address).call()
            logger.debug(f"sender_allowance_usdc: {sender_allowance_usdc}") # 无穷大 115792089237316195423570985008687907853269984665640564039457584007913129.639935

            # USDC余额不足
            inviter_price = 12000000 # 12 USDC
            if inviter_price > sender_balance_usdc:
                # logger.error(f"Ooops! Insufficient USDC balance.")
                raise Exception("Insufficient USDC balance.")
                return "Insufficient USDC balance."

            # 购卡合约USDC授权额度不足
            if inviter_price > sender_allowance_usdc:
                logger.error(f"Ooops! Insufficient USDC authorization amount for invite_contract.")
                # raise Exception("Insufficient USDC authorization amount for invite_contract.")

                # 使用公共函数构建基础交易参数
                base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
                # 构建交易 - 购卡合约金额授权
                transaction = usdc_contract.functions.approve(invite_address, inviter_price).build_transaction(base_transaction)
                logger.debug(f"approve transaction: {transaction}")

                # 发送交易
                tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # usdc.approve
                if tx_success == False:
                    logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                    raise Exception("Failed to send_transaction.")
                
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The approve transaction send successfully! - transaction: {transaction}")

            # --------------------------------------------------------------------------

            referral_addr = random.choice(REFERRAL_ADDRESS)
            referral_address = Web3.to_checksum_address(referral_addr)
            logger.debug(f"referral_address: {referral_address}")
            
            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 购卡
            transaction = invite_contract.functions.inviter( referral_address ).build_transaction(base_transaction)
            logger.debug(f"inviter transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # invite.inviter
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")
            else:
                # -------------------------------------------------------------------------- godhoodemotion
                clicker_response = await self.godhoodemotion_clicker(sender_address)
                if clicker_response is None:
                    return "ERROR"
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion response: {clicker_response}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The inviter transaction send successfully! - transaction: {transaction}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid_buy_clicker except: {error}")

    async def godhoodemotion_clicker(self, eth_address) -> None:
        try:
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- godhoodid
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion_clicker {response}")

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

    async def godhoodtransfer_clicker(self, eth_address) -> None:
        try:
            headers = self.getheaders()

            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- godhood_transfer
            url = GAEA_API.rstrip('/')+'/api/godhood/transfer'
            json_data = {
                "chain_id": 8453,
                "wallet_address": sender_address,
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer_clicker except: {error}")

    async def godhoodreward_clicker(self, eth_address) -> None:
        try:
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- invite
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 购卡合约地址
            invite_address = Web3.to_checksum_address(CONTRACT_INVITE)
            invite_contract = web3_obj.eth.contract(address=invite_address, abi=contract_abi_invite)

            # 余额查询
            invite_sender_usdc = invite_contract.functions.invitereward( sender_address ).call()
            logger.debug(f"invite_sender_usdc: {invite_sender_usdc}")
            reward_usdc = web3_obj.from_wei(invite_sender_usdc, 'mwei')
            logger.debug(f"reward_usdc: {reward_usdc}")

            # if reward_usdc < 10.0: # 余额大于10USDC显示绿色
            #     logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
            # else:
            #     logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
            return reward_usdc # 'SUCCESS'
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodreward_clicker except: {error}")

    async def godhoodclaimed_clicker(self, eth_address) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodclaimed_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            # -------------------------------------------------------------------------- invite
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # 购卡合约地址
            invite_address = Web3.to_checksum_address(CONTRACT_INVITE)
            invite_contract = web3_obj.eth.contract(address=invite_address, abi=contract_abi_invite)

            # 余额查询
            invite_sender_usdc = invite_contract.functions.invitereward( sender_address ).call()
            logger.debug(f"invite_sender_usdc: {invite_sender_usdc}")
            reward_usdc = web3_obj.from_wei(invite_sender_usdc, 'mwei')
            logger.debug(f"reward_usdc: {reward_usdc}")

            if reward_usdc < 10.0: # 余额大于10USDC才能提现
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
                return 'ERROR'
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
            
            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 提现
            transaction = invite_contract.functions.claimrewards( ).build_transaction(base_transaction)
            logger.debug(f"claimrewards transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # invite.claimrewards
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")

            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The claimrewards transaction send successfully! - reward_usdc: {reward_usdc}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodclaimed_clicker except: {error}")

    ## 购票
    async def ticket_generate_clicker(self, level: int| None = 1) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- ticketbox_generate
            url = GAEA_API.rstrip('/')+'/api/ticket/generate?level='+str(level)

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_generate_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_generate_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_generate_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_generate_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_generate_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_generate_clicker except: {error}")

    async def ticket_buy_clicker(self, tick_level, tick_rebate, final_hash) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_buy_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_buy_clicker tick_level: {tick_level}")
            # -------------------------------------------------------------------------- ticket_buy
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            if sender_balance_eth == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 账户余额为0")
                return "ERRRO"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")

            # 购票合约地址
            ticket_address = Web3.to_checksum_address(CONTRACT_TICKET)
            ticket_contract = web3_obj.eth.contract(address=ticket_address, abi=contract_abi_ticket)

            if tick_level==1:
                # 是否购买过超级折扣
                ticket_level_one = ticket_contract.functions.hasPurchasedLevel1( sender_address ).call()
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} | ticket_level_one: {ticket_level_one}")
                if ticket_level_one:
                    logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} | Already purchased level1")
                    raise Exception("Already purchased level1")

            # 查询票价
            ticket_info = ticket_contract.functions.getTicketLevel( tick_level ).call()
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} | ticket_info: {ticket_info}")
            ticket_price = ticket_info[0]
            if ticket_price == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_price: {ticket_price}")
                raise Exception("ticket_price: 0")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_price: {ticket_price}")
            # --------------------------------------------------------------------------

            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            # 购卡合约授权金额
            sender_allowance_usdc = usdc_contract.functions.allowance(sender_address, ticket_address).call()
            logger.debug(f"sender_allowance_usdc: {sender_allowance_usdc}") # 无穷大 115792089237316195423570985008687907853269984665640564039457584007913129.639935

            # USDC余额不足
            if ticket_price > sender_balance_usdc:
                # logger.error(f"Ooops! Insufficient USDC balance.")
                raise Exception("Insufficient USDC balance.")
                return "Insufficient USDC balance."

            # 购票合约USDC授权额度不足
            if ticket_price > sender_allowance_usdc:
                logger.error(f"Ooops! Insufficient USDC authorization amount for ticket_contract.")
                # raise Exception("Insufficient USDC authorization amount for ticket_contract.")

                # 使用公共函数构建基础交易参数
                base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
                # 构建交易 - 购卡合约金额授权
                transaction = usdc_contract.functions.approve(ticket_address, ticket_price).build_transaction(base_transaction)
                logger.debug(f"approve transaction: {transaction}")

                # 发送交易
                tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # usdc.approve
                if tx_success == False:
                    logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                    raise Exception("Failed to send_transaction.")
                
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The approve transaction send successfully! - transaction: {transaction}")

            # --------------------------------------------------------------------------

            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 购买
            transaction = ticket_contract.functions.buyTickets(tick_level,tick_rebate,final_hash).build_transaction(base_transaction)
            logger.debug(f"buyTickets transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # ticket.buyTickets
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The buyTickets transaction send successfully! - tick_level: {tick_level} tick_rebate: {tick_rebate}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_buy_clicker except: {error}")

    ## 深度训练
    async def is_deeptrain_clicker(self, eth_address) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- isdeeptrain
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 情绪合约地址
            emotion_address = Web3.to_checksum_address(CONTRACT_EMOTION)
            if ERA3_ONLINE_STAMP > current_timestamp:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion)
            elif EMOTION3_ONLINE_STAMP > current_timestamp:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion2)
            else:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion3)

            if EMOTION3_ONLINE_STAMP > current_timestamp:
                # 当期ID
                current_period_id = emotion_contract.functions.Issue().call()
                logger.debug(f"current_period_id: {current_period_id}")
                time.sleep(1)
                # 当前是否打卡
                current_emotion = emotion_contract.functions.IssueAddressEmotions(current_period_id, sender_address).call()
                logger.debug(f"current_emotion: {current_emotion}")
                time.sleep(1)
            else:
                # 当前是否打卡
                current_emotion = emotion_contract.functions.isBet(sender_address).call()
                logger.debug(f"current_emotion: {current_emotion}")
                time.sleep(1)

            if current_emotion > 0: # 
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Deeptrain already completed | emotion: {current_emotion}")
                return True
            return False
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} is_deeptrain_clicker except: {error}")
            return False

    async def deeptrain_clicker(self, emotion_detail, eth_address) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            emotion_int = emotion_detail.split('_')[0]
            
            emotion_int = int(emotion_int)
            if emotion_int not in [1,2,3]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker ERROR: Wrong emotion_int: {emotion_int}")
                raise Exception(f'Wrong emotion_int: {emotion_int}')
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker emotion_int: {emotion_int}")
            # -------------------------------------------------------------------------- deeptrain
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # 情绪合约地址
            emotion_address = Web3.to_checksum_address(CONTRACT_EMOTION)
            if ERA3_ONLINE_STAMP > current_timestamp:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion)
            elif EMOTION3_ONLINE_STAMP > current_timestamp:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion2)
            else:
                emotion_contract = web3_obj.eth.contract(address=emotion_address, abi=contract_abi_emotion3)

            if EMOTION3_ONLINE_STAMP > current_timestamp:
                # 当期ID
                current_period_id = emotion_contract.functions.Issue().call()
                logger.debug(f"current_period_id: {current_period_id}")
                time.sleep(1)
                # 当前是否打卡
                current_emotion = emotion_contract.functions.IssueAddressEmotions(current_period_id, sender_address).call()
                logger.debug(f"current_emotion: {current_emotion}")
                time.sleep(1)

                if current_emotion > 0: # 
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Deeptrain already completed | emotion: {current_emotion}")
                    return 'Deeptrain already completed'

                # 当期信息
                current_period_info = emotion_contract.functions.IssueInformation(current_period_id).call()
                logger.debug(f"current_period_info: {current_period_info}")
                current_period_price = current_period_info[1]  # 当期单价
                logger.debug(f"current_period_price: {current_period_price}")
                end_timestamp = current_period_info[0]  # 当期结束时间戳
                logger.debug(f"end_timestamp: {end_timestamp}")
            else:
                # 当前是否打卡
                current_emotion = emotion_contract.functions.isBet(sender_address).call()
                logger.debug(f"current_emotion: {current_emotion}")
                time.sleep(1)

                if current_emotion > 0: # 
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Deeptrain already completed | emotion: {current_emotion}")
                    return 'Deeptrain already completed'

                # 查询信息
                before_base_Info = emotion_contract.functions.getBaseInfo().call()
                logger.debug(f"before_base_Info: {before_base_Info}")  # [1, 100000000, 1, 1, 400000, 0, 0]
                # period_id = before_base_Info[0]  # 当期ID
                # period_putmoney = before_base_Info[1]  # 当期底仓USD
                current_period_price = before_base_Info[2]   # 当期单价
                end_timestamp = before_base_Info[3] # 当期结束时间戳
                # period_duration = before_base_Info[4] # 当期时长
                # period_poolmoney = before_base_Info[5] # 当期USD池
                # period_status = before_base_Info[6]  # 当期状态
                # start_stamp = end_timestamp - period_duration # 阶段开始时间戳
                logger.debug(f"current_period_price: {current_period_price}")
                logger.debug(f"end_timestamp: {end_timestamp}")
            
            # 时间已结束
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")
            if end_timestamp < current_timestamp:
                logger.info(f"The {current_period_id} period is over.")
                return f"The {current_period_id} period is over."

            # --------------------------------------------------------------------------

            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            # 情绪合约授权金额
            sender_allowance_usdc = usdc_contract.functions.allowance(sender_address, emotion_address).call()
            logger.debug(f"sender_allowance_usdc: {sender_allowance_usdc}") # 无穷大 115792089237316195423570985008687907853269984665640564039457584007913129.639935

            # USDC余额不足
            if current_period_price > sender_balance_usdc:
                # logger.error(f"Ooops! Insufficient USDC balance.")
                raise Exception("Insufficient USDC balance.")
                return "Insufficient USDC balance."
            
            # 情绪合约USDC授权额度不足
            if current_period_price > sender_allowance_usdc:
                logger.error(f"Ooops! Insufficient USDC authorization amount for emotion_contract.")
                # raise Exception("Insufficient USDC authorization amount for emotion_contract.")

                # 使用公共函数构建基础交易参数
                base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
                # 构建交易 - 情绪合约金额授权
                MAX_UINT256 = 2**256 - 1 # 无穷大 current_period_price
                transaction = usdc_contract.functions.approve(emotion_address, MAX_UINT256).build_transaction(base_transaction)
                logger.debug(f"approve transaction: {transaction}")

                # 发送交易
                tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # usdc.approve
                if tx_success == False:
                    logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                    raise Exception("Failed to send_transaction.")
                
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The approve transaction send successfully! - transaction: {transaction}")

            # --------------------------------------------------------------------------

            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 情绪打卡
            if ERA3_ONLINE_STAMP > current_timestamp:
                transaction = emotion_contract.functions.emotions( emotion_int ).build_transaction(base_transaction)
            elif EMOTION3_ONLINE_STAMP > current_timestamp:
                transaction = emotion_contract.functions.emotions( sender_address, emotion_int ).build_transaction(base_transaction)
            else:
                transaction = emotion_contract.functions.bet( sender_address, emotion_int ).build_transaction(base_transaction)
            logger.debug(f"emotions transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # emotion.bet
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")
            
            logger.info(f"The emotions transaction send successfully! - transaction: {transaction}")
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Deeptrain successfully! - emotion: {emotion_int}")
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deeptrain_clicker except: {error}")

    async def ticket_deeptrain_clicker(self, ticket, emotion_detail) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- ticket_deeptrain
            url = GAEA_API.rstrip('/')+'/api/emotion/complete'
            json_data = {
                "chain_id": 8453,
                "detail": emotion_detail,
                "ticket": ticket,
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deeptrain_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deeptrain_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deeptrain_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deeptrain_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deeptrain_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deeptrain_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deeptrain_clicker except: {error}")

    async def emotionreward_clicker(self, eth_address) -> None:
        try:
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- Reward
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 情绪提现合约地址
            reward_address = Web3.to_checksum_address(CONTRACT_REWARD)

            # 余额查询
            if EMOTION3_ONLINE_STAMP > current_timestamp:
                reward_contract = web3_obj.eth.contract(address=reward_address, abi=contract_abi_reward)
                reward_sender_usdc = reward_contract.functions.getReward( sender_address ).call()
            else:
                reward_contract = web3_obj.eth.contract(address=reward_address, abi=contract_abi_reward3)
                reward_sender_usdc = reward_contract.functions.getRewards( sender_address ).call()
            logger.debug(f"reward_sender_usdc: {reward_sender_usdc}")
            reward_usdc = web3_obj.from_wei(reward_sender_usdc, 'mwei')
            logger.debug(f"reward_usdc: {reward_usdc}")

            # if reward_usdc < 5.0: # 余额大于5USDC显示绿色
            #     logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
            # else:
            #     logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
            return reward_usdc # 'SUCCESS'
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionreward_clicker except: {error}")

    async def emotionclaimed_clicker(self, eth_address) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionclaimed_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionclaimed_clicker eth_address: {eth_address[:10]}")
            # -------------------------------------------------------------------------- Reward
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # 情绪提现合约地址
            reward_address = Web3.to_checksum_address(CONTRACT_REWARD)

            # 余额查询
            if EMOTION3_ONLINE_STAMP > current_timestamp:
                reward_contract = web3_obj.eth.contract(address=reward_address, abi=contract_abi_reward)
                reward_sender_usdc = reward_contract.functions.getReward( sender_address ).call()
            else:
                reward_contract = web3_obj.eth.contract(address=reward_address, abi=contract_abi_reward3)
                reward_sender_usdc = reward_contract.functions.getRewards( sender_address ).call()
            logger.debug(f"reward_sender_usdc: {reward_sender_usdc}")
            reward_usdc = web3_obj.from_wei(reward_sender_usdc, 'mwei')
            logger.debug(f"reward_usdc: {reward_usdc}")

            if reward_usdc < 5.0: # 余额大于5USDC再提现
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
                return 'ERROR'
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} reward_usdc: {reward_usdc}")
            
            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 提现
            transaction = reward_contract.functions.claim().build_transaction(base_transaction)
            logger.debug(f"claim transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # reward.claim
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The claim transaction send successfully! - reward_usdc: {reward_usdc}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionclaimed_clicker except: {error}")

    ## 深度抉择
    async def deepchoice_list_clicker(self) -> None:
        remainingOptions = [1,2,3,4]
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # -------------------------------------------------------------------------- deepchoice_list
            web3_obj = self._web3_instance
            
            # 情绪合约地址
            choice_address = Web3.to_checksum_address(CONTRACT_CHOICE)
            choice_contract = web3_obj.eth.contract(address=choice_address, abi=contract_abi_choice)
            # 查询当前epoch
            epoch_id = choice_contract.functions.currentEpoch().call()
            # 查询投注结果: mainstreams/eliminateds
            results_info = choice_contract.functions.getEpochBetResults(epoch_id).call()
            logger.debug(f"results_info: {results_info}")
            mainstreams = results_info[0]  # 各选项投注人数
            eliminateds = results_info[1]  # 各选项投注Soul数
            logger.debug(f"mainstreams: {mainstreams} eliminateds: {eliminateds}")
            # 当前可用选项
            for eliminated in eliminateds:
                if eliminated != 0:
                    remainingOptions.remove(eliminated)
            logger.debug(f"remainingOptions: {remainingOptions}")
            
            return remainingOptions
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deepchoice_list_clicker except: {error}")
            return remainingOptions

    async def is_deepchoice_clicker(self, eth_address) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- isdeepchoice
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 情绪合约地址
            choice_address = Web3.to_checksum_address(CONTRACT_CHOICE)
            choice_contract = web3_obj.eth.contract(address=choice_address, abi=contract_abi_choice)

            # 当前是否打卡
            current_choice = choice_contract.functions.isBet(sender_address).call()
            logger.debug(f"current_choice: {current_choice}")
            time.sleep(1)

            if current_choice > 0: # 
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Deepchoice already completed | choice: {current_choice}")
                return True
            return False
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} is_deepchoice_clicker except: {error}")
            return False

    async def deepchoice_clicker(self, choice_detail, eth_address) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deepchoice_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            choice_int = choice_detail.split('_')[0]
            choice_int = int(choice_int)
            if choice_int not in [1,2,3,4]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deepchoice_clicker ERROR: Wrong choice_int: {choice_int}")
                raise Exception(f'Wrong choice_int: {choice_int}')
            
            soul_int = choice_detail.split('_')[1]
            soul_int = int(soul_int)
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deepchoice_clicker choice_int: {choice_int}")
            # -------------------------------------------------------------------------- deepchoice
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # 抉择合约地址
            choice_address = Web3.to_checksum_address(CONTRACT_CHOICE)
            choice_contract = web3_obj.eth.contract(address=choice_address, abi=contract_abi_choice)

            # 当前是否打卡
            current_choice = choice_contract.functions.isBet(sender_address).call()
            logger.debug(f"current_choice: {current_choice}")
            time.sleep(1)

            if current_choice > 0: # 
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Deepchoice already completed | choice: {current_choice}")
                return 'Deepchoice already completed'

            # 当期信息
            current_period_info = choice_contract.functions.getBaseInfo().call()
            logger.debug(f"current_period_info: {current_period_info}")
            current_epoch_id = current_period_info[0]
            current_phase_id = current_period_info[3]
            current_period_id = (int(current_epoch_id)-1)*3 + int(current_phase_id) if current_epoch_id>0 else 0  # 当期ID
            current_period_price = current_period_info[5]  # 当期单价
            logger.debug(f"current_period_price: {current_period_price}")
            end_timestamp = current_period_info[6]  # 当期结束时间戳
            logger.debug(f"end_timestamp: {end_timestamp}")
            
            # 时间已结束
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")
            if end_timestamp < current_timestamp:
                logger.info(f"The {current_period_id} period is over.")
                return f"The {current_period_id} period is over."

            # --------------------------------------------------------------------------

            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # 账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            # 情绪合约授权金额
            sender_allowance_usdc = usdc_contract.functions.allowance(sender_address, choice_address).call()
            logger.debug(f"sender_allowance_usdc: {sender_allowance_usdc}") # 无穷大 115792089237316195423570985008687907853269984665640564039457584007913129.639935

            # USDC余额不足
            if current_period_price > sender_balance_usdc:
                # logger.error(f"Ooops! Insufficient USDC balance.")
                raise Exception("Insufficient USDC balance.")
                return "Insufficient USDC balance."
            
            # 情绪合约USDC授权额度不足
            if current_period_price > sender_allowance_usdc:
                logger.error(f"Ooops! Insufficient USDC authorization amount for choice_contract.")
                # raise Exception("Insufficient USDC authorization amount for choice_contract.")

                # 使用公共函数构建基础交易参数
                base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
                # 构建交易 - 情绪合约金额授权
                MAX_UINT256 = 2**256 - 1 # 无穷大 current_period_price
                transaction = usdc_contract.functions.approve(choice_address, MAX_UINT256).build_transaction(base_transaction)
                logger.debug(f"approve transaction: {transaction}")

                # 发送交易
                tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # usdc.approve
                if tx_success == False:
                    logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                    raise Exception("Failed to send_transaction.")

                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The approve transaction send successfully! - transaction: {transaction}")

            # --------------------------------------------------------------------------

            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 情绪打卡
            transaction = choice_contract.functions.bet( sender_address, choice_int, soul_int ).build_transaction(base_transaction)
            logger.debug(f"choices transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # choice.bet
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")

            logger.info(f"The choices transaction send successfully! - transaction: {transaction}")
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Deepchoice successfully! - choice: {choice_int}")
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} deepchoice_clicker except: {error}")

    async def ticket_deepchoice_clicker(self, ticket, choice_detail) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- ticket_deepchoice
            url = GAEA_API.rstrip('/')+'/api/choice/complete'
            json_data = {
                "chain_id": 8453,
                "detail": choice_detail,
                "ticket": ticket,
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker except: {error}")

    async def choicereward_clicker(self, eth_address) -> None:
        try:
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- Reward
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 抉择提现合约地址
            award_address = Web3.to_checksum_address(CONTRACT_AWARD)
            award_contract = web3_obj.eth.contract(address=award_address, abi=contract_abi_award)

            # 余额查询
            award_sender_usdc = award_contract.functions.getRewards( sender_address ).call()
            logger.debug(f"award_sender_usdc: {award_sender_usdc}")
            award_usdc = web3_obj.from_wei(award_sender_usdc, 'mwei')
            logger.debug(f"award_usdc: {award_usdc}")

            # if award_usdc < 5.0: # 余额大于5USDC显示绿色
            #     logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} award_usdc: {award_usdc}")
            # else:
            #     logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} award_usdc: {award_usdc}")
            return award_usdc # 'SUCCESS'
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choicereward_clicker except: {error}")

    async def choiceclaimed_clicker(self, eth_address) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceclaimed_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceclaimed_clicker eth_address: {eth_address[:10]}")
            # -------------------------------------------------------------------------- Reward
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # 情绪提现合约地址
            award_address = Web3.to_checksum_address(CONTRACT_AWARD)
            award_contract = web3_obj.eth.contract(address=award_address, abi=contract_abi_award)

            # 余额查询
            award_sender_usdc = award_contract.functions.getRewards( sender_address ).call()
            logger.debug(f"award_sender_usdc: {award_sender_usdc}")
            award_usdc = web3_obj.from_wei(award_sender_usdc, 'mwei')
            logger.debug(f"award_usdc: {award_usdc}")

            if award_usdc < 5.0: # 余额大于5USDC再提现
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} award_usdc: {award_usdc}")
                return 'ERROR'
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} award_usdc: {award_usdc}")
            
            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 提现
            transaction = award_contract.functions.claim().build_transaction(base_transaction)
            logger.debug(f"claim transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # award.claim
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")

            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The claim transaction send successfully! - award_usdc: {award_usdc}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceclaimed_clicker except: {error}")

    ## NFT供奉 snft
    async def snft_ismint_clicker(self, eth_address) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- is_snftmint
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # NFT合约地址
            snftmint_address = Web3.to_checksum_address(CONTRACT_SNFTMINT)
            snftmint_contract = web3_obj.eth.contract(address=snftmint_address, abi=contract_abi_mint)
        
            # 当前NFT等级
            current_nftlevel = snftmint_contract.functions.getTokenLevel(sender_address).call()
            logger.debug(f"current_nftlevel: {current_nftlevel}")
            time.sleep(1)

            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft mint already completed | current_nftlevel: {current_nftlevel}")
            return current_nftlevel
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_ismint_clicker except: {error}")
            return 0

    async def snft_generate_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- generate
            url = GAEA_API.rstrip('/')+'/api/nft/generate'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_generate_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_generate_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_generate_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_generate => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_generate_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_generate_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft_generate_clicker except: {error}")

    async def snftmint_clicker(self, eth_address, nft_level,block_number, final_hash) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftmint_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftmint_clicker eth_address: {eth_address[:10]}")
            # -------------------------------------------------------------------------- snftmint
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            if sender_balance_eth == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 账户余额为0")
                return "ERRRO"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # NFT铸造合约地址
            snftmint_address = Web3.to_checksum_address(CONTRACT_SNFTMINT)
            snftmint_contract = web3_obj.eth.contract(address=snftmint_address, abi=contract_abi_mint)

            # 等级查询
            snftmint_id = snftmint_contract.functions.getTokenID( sender_address ).call()
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} snftmint_id: {snftmint_id}")
            
            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 铸造
            if snftmint_id==0:
                transaction = snftmint_contract.functions.mintNFT(nft_level,block_number,final_hash).build_transaction(base_transaction)
                logger.debug(f"mintNFT transaction: {transaction}")
            else:
                transaction = snftmint_contract.functions.upgradeNFT(snftmint_id, nft_level,block_number,final_hash).build_transaction(base_transaction)
                logger.debug(f"upgradeNFT transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # snftmint.mintNFT
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")

            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The { 'mintNFT' if snftmint_id==0 else 'upgradeNFT' } transaction send successfully! - snftmint_id: {snftmint_id} nft_level: {nft_level}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftmint_clicker except: {error}")

    async def snftlist_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- snftlist
            url = GAEA_API.rstrip('/')+'/api/nft/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist_clicker except: {error}")

    async def snftoblate_clicker(self, tokenids) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- snftoblate
            url = GAEA_API.rstrip('/')+'/api/nft/claimed'
            json_data = {
                "tokens": tokenids
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate_clicker except: {error}")

    ## NFT供奉 anft
    async def anft_ismint_clicker(self, eth_address) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # # 钱包地址
            # sender_address = Web3().eth.account.from_key(self.client.prikey).address
            # 钱包地址
            sender_address = Web3.to_checksum_address(eth_address)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]}")

            # -------------------------------------------------------------------------- is_anftmint
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # NFT合约地址
            anftmint_address = Web3.to_checksum_address(CONTRACT_ANFTMINT)
            anftmint_contract = web3_obj.eth.contract(address=anftmint_address, abi=contract_abi_mint)
        
            # 当前NFT等级
            current_nftticket = anftmint_contract.functions.getTokenTicket(sender_address).call()
            logger.debug(f"current_nftticket: {current_nftticket}")
            time.sleep(1)

            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft mint already completed | current_nftticket: {current_nftticket}")
            return current_nftticket
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_ismint_clicker except: {error}")
            return 0

    async def anft_generate_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- generate
            url = GAEA_API.rstrip('/')+'/api/nft/anniversary/generate'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_generate_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_generate_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_generate_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_generate_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_generate_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_generate_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft_generate_clicker except: {error}")

    async def anftmint_clicker(self, eth_address, nft_ticket,block_number, final_hash) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftmint_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftmint_clicker eth_address: {eth_address[:10]}")
            # -------------------------------------------------------------------------- anftmint
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            if sender_balance_eth == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 账户余额为0")
                return "ERRRO"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # NFT铸造合约地址
            anftmint_address = Web3.to_checksum_address(CONTRACT_ANFTMINT)
            anftmint_contract = web3_obj.eth.contract(address=anftmint_address, abi=contract_abi_mint)

            # 等级查询
            anftmint_id = anftmint_contract.functions.getTokenID( sender_address ).call()
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} anftmint_id: {anftmint_id}")
            
            # 使用公共函数构建基础交易参数
            base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            # 构建交易 - 铸造
            if anftmint_id==0:
                transaction = anftmint_contract.functions.mintNFT(nft_ticket,block_number,final_hash).build_transaction(base_transaction)
                logger.debug(f"mintNFT transaction: {transaction}")
            else:
                transaction = anftmint_contract.functions.upgradeNFT(anftmint_id, nft_ticket,block_number,final_hash).build_transaction(base_transaction)
                logger.debug(f"upgradeNFT transaction: {transaction}")

            # 发送交易
            tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # anftmint.mintNFT
            if tx_success == False:
                logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                raise Exception("Failed to send_transaction.")

            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The { 'mintNFT' if anftmint_id==0 else 'upgradeNFT' } transaction send successfully! - anftmint_id: {anftmint_id} nft_ticket: {nft_ticket}")
            return "SUCCESS"
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftmint_clicker except: {error}")

    async def anftlist_clicker(self) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- anftlist
            url = GAEA_API.rstrip('/')+'/api/nft/anniversary/list'

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist_clicker url: {url}")
            response = await self.client.make_request(
                method='GET', 
                url=url, 
                headers=headers,
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist_clicker => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist_clicker except: {error}")

    async def anftoblate_clicker(self, tokenids) -> None:
        try:
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            # -------------------------------------------------------------------------- anftoblate
            url = GAEA_API.rstrip('/')+'/api/nft/anniversary/claimed'
            json_data = {
                "tokens": tokenids
            }

            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate_clicker url: {url}")
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate_clicker json_data: {json_data}")
            response = await self.client.make_request(
                method='POST', 
                url=url, 
                headers=headers,
                json=json_data
            )
            if 'ERROR' in response:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate_clicker {response}")
                raise Exception(response)
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} => {response['data']}")
                return response['data']
            else:
                message = response.get('msg', None)
                if message is None:
                    message = f"{response.get('detail', None)}" 
                if message.find('completed') > 0:
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate_clicker => {message}")
                    return message
                else:
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate_clicker ERROR: {message}")
                    raise Exception(message)
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate_clicker except: {error}")

    ## 汇聚
    async def fundsreward_clicker(self, eth_address) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftmint_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # -------------------------------------------------------------------------- balanceOf
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            if sender_balance_eth == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 账户余额为0")
                return "ERRRO"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # SXP合约地址
            sxp_address = Web3.to_checksum_address(CONTRACT_SXP)
            sxp_contract = web3_obj.eth.contract(address=sxp_address, abi=contract_abi_usdc)

            # USDC账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            sender_usdc = web3_obj.from_wei(sender_balance_usdc, 'mwei')
            logger.debug(f"sender_usdc: {sender_usdc}")
            # SXP账户余额
            sender_balance_sxp = sxp_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_sxp: {sender_balance_sxp}")
            sender_sxp = web3_obj.from_wei(sender_balance_sxp, 'mwei')
            logger.debug(f"sender_sxp: {sender_sxp}")

            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - usdc: {sender_usdc} sxp: {sender_sxp}")

            # if sender_usdc < 5.0: # 余额大于5USDC显示绿色
            #     logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} sender_usdc: {sender_usdc}")
            # else:
            #     logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} sender_usdc: {sender_usdc}")
            return sender_usdc # 'SUCCESS'
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} fundsreward_clicker except: {error}")
            return 0

    async def fundspooling_clicker(self, eth_address, is_all=False) -> None:
        try:
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftmint_clicker ERROR: Incorrect private key")
                raise Exception(f"Incorrect private key")
            
            headers = self.getheaders()
            if len(headers.get('Authorization', None)) < 50:
                # -------------------------------------------------------------------------- login
                login_response = await self.login_clicker()
                self.client.token = login_response.get('token', None)
                set_data_for_token(self.client.runname, self.client.id, self.client.token)
                self.client.userid = login_response.get('user_info', None).get('uid', None)
                set_data_for_userid(self.client.runname, self.client.id, self.client.userid)
            
            # -------------------------------------------------------------------------- balanceOf
            web3_obj = self._web3_instance
            
            current_timestamp = int(time.time())
            logger.debug(f"current_timestamp: {current_timestamp}")

            # 钱包地址
            sender_address = web3_obj.eth.account.from_key(self.client.prikey).address
            sender_balance_eth = web3_obj.eth.get_balance(sender_address)
            if sender_balance_eth == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 账户余额为0")
                return "ERRRO"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} balance: {web3_obj.from_wei(sender_balance_eth, 'ether')} ETH")
            if eth_address.lower() != sender_address.lower():
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} != eth_address: {eth_address[:10]}")
                raise Exception("Does not match the binding address.")

            # USDC合约地址
            usdc_address = Web3.to_checksum_address(CONTRACT_USDC)
            usdc_contract = web3_obj.eth.contract(address=usdc_address, abi=contract_abi_usdc)
            # SXP合约地址
            sxp_address = Web3.to_checksum_address(CONTRACT_SXP)
            sxp_contract = web3_obj.eth.contract(address=sxp_address, abi=contract_abi_usdc)

            # 归集地址选择
            pooling_addr = ''
            pooling_addr_dict = json.loads(POOLING_ADDRESS)
            pooling_addr_items = pooling_addr_dict.get(self.client.runname, None)
            for pooling_addr_item in pooling_addr_items:
                if pooling_addr_item.get('min', 0) <= self.client.id <= pooling_addr_item.get('max', 0):
                    pooling_addr = pooling_addr_item.get('address', None)
                    break
            if pooling_addr == '' or len(pooling_addr) != 42:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: Incorrect pooling address")
                raise Exception(f"Incorrect pooling address")
            pooling_address = Web3.to_checksum_address(pooling_addr)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} sender_address: {sender_address[:10]} pooling_address: {pooling_address}")
            
            # USDC账户余额
            sender_balance_usdc = usdc_contract.functions.balanceOf(sender_address).call()
            logger.debug(f"sender_balance_usdc: {sender_balance_usdc}")
            sender_usdc = web3_obj.from_wei(sender_balance_usdc, 'mwei')
            logger.debug(f"sender_usdc: {sender_usdc}")
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - usdc: {sender_usdc}")
            time.sleep(1)
            if 10000000 < sender_balance_usdc and pooling_addr != '': # 大于10开始归集USDC
                if is_all: # 归集全部USDC
                    balance_usdc = sender_balance_usdc
                else: # 归集大于5的USDC
                    balance_usdc = sender_balance_usdc - sender_balance_usdc%5000000
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - balance_usdc: {balance_usdc}")
                
                # 使用公共函数构建基础交易参数
                base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
                # 构建交易 - 转账
                transaction = usdc_contract.functions.transfer(pooling_address, balance_usdc).build_transaction(base_transaction)
                logger.debug(f"transfer transaction: {transaction}")

                # 发送交易
                tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # usdc.transfer
                if tx_success == False:
                    logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
                    raise Exception("Failed to send_transaction.")

                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The transfer transaction send successfully! - usdc: {balance_usdc/1_000_000}")
            
            # # SXP账户余额
            # sender_balance_sxp = sxp_contract.functions.balanceOf(sender_address).call()
            # logger.debug(f"sender_balance_sxp: {sender_balance_sxp}")
            # sender_sxp = web3_obj.from_wei(sender_balance_sxp, 'mwei')
            # logger.debug(f"sender_sxp: {sender_sxp}")
            # logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - sxp: {sender_sxp}")
            # time.sleep(1)
            # if 100000000 < sender_balance_sxp and pooling_addr != '': # 大于100开始归集SXP
            #     # 使用公共函数构建基础交易参数
            #     base_transaction = self.build_base_transaction(web3_obj, sender_address, WEB3_CHAINID)
            #     # 构建交易 - 转账
            #     transaction = sxp_contract.functions.transfer(pooling_address, sender_balance_sxp).build_transaction(base_transaction)
            #     logger.debug(f"transfer transaction: {transaction}")

            #     # 发送交易
            #     tx_success, tx_msg = self.send_transaction_with_retry(web3_obj, transaction, self.client.prikey) # sxp.transfer
            #     if tx_success == False:
            #         logger.error(f"Ooops! Failed to send_transaction. tx_msg: {tx_msg}")
            #         raise Exception("Failed to send_transaction.")

            #     logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The transfer transaction send successfully! - sxp: {sender_sxp}")
            
            return sender_usdc
        except Exception as error:
            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} fundspooling_clicker except: {error}")
            return 0

    # -------------------------------------------------------------------------- 过期任务

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin_clicker => {response['data']}")
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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker {response}")

            code = response.get('code', None)
            if code in [200, 201]:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin_clicker => {response['data']}")
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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list_clicker {response}")

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
            # logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete_clicker {response}")

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
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} checkin response: {clicker_response}")
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
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} signin response: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_signin except: {error}")
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
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_list response: {clicker_response}")
            
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
                    logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete response: {clicker_response}")

                    idx+=1
                    delay = random.randint(10, 20)
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete delay: {delay} seconds")
                    await asyncio.sleep(delay)
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} referral_complete count: {idx}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_referralreword except: {error}")
            return f"ERROR: {error}"

    # --------------------------------------------------------------------------

    ## 基础任务
    @helper
    async def daily_clicker_register(self):
        try:
            if len(self.client.userid) > 5:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Already registered")
                return "SUCCESS"
            
            if len(REFERRAL_CODE) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} REFERRAL_CODE is Null")
                raise Exception("REFERRAL_CODE is Null")
            # -------------------------------------------------------------------------- register
            clicker_response = await self.register_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} register response: {clicker_response}")
            
            self.client.userid = clicker_response.get('uid', None)
            set_data_for_userid(self.client.runname, self.client.id, self.client.userid)

            clicker_response.pop('referral_link', None)
            clicker_response.pop('avatar', None)
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Registered successfully - userid: {clicker_response['uid']}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_register except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_login(self):
        try:
            if len(self.client.token) > 5:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Already login")
                return "SUCCESS"
            
            # -------------------------------------------------------------------------- login
            clicker_response = await self.login_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} login response: {clicker_response}")
            
            self.client.token = clicker_response.get('token', None)
            set_data_for_token(self.client.runname, self.client.id, self.client.token)
            self.client.userid = clicker_response.get('user_info', None).get('uid', None)
            set_data_for_userid(self.client.runname, self.client.id, self.client.userid)

            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Login successfully - userinfo: {clicker_response['user_info']}")
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
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - username: {clicker_response['name']} eth_address: {eth_address[:10]} medal: {clicker_response['medal']} medal_expired: {((clicker_response['medal_expired']-int(time.time()))/60/60/24 if clicker_response['medal'] else 0):.2f} days")
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
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} earninfo response: {clicker_response}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - era_gaea: {clicker_response['era_gaea']} era_soul: {clicker_response['era_soul']} total_soul: {clicker_response['total_soul']} today_uptime: {(clicker_response['today_uptime']/60):.2f} hours")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_earninfo except: {error}")
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
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} era3_info response: {clicker_response}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - userinfo: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_era3info except: {error}")
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
            clicker_response = await self.session_clicker() # bindaddress
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} eth_address: {clicker_response['eth_address']}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is not None and eth_address != "":
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The address has been bound")
                return "SUCCESS"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- bindaddress
            clicker_response = await self.bind_address_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bindaddress response: {clicker_response}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_bindaddress except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_openblindbox(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- godhoodinfo
            clicker_response = await self.godhoodinfo_clicker() # mood
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
            
            if clicker_response['mood'] is None:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: Please mint GODHOOD ID first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            cdkeys_len = 0
            total = 1
            while total > 0:
                # -------------------------------------------------------------------------- blindbox_list
                clicker_response = await self.blindbox_list_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list response: {clicker_response}")
                cdkeys = clicker_response.get("cdkeys", [])
                total = clicker_response.get("total", 0)
                cdkeys_len = len(cdkeys)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list cdkeys: {cdkeys} cdkeys_len: {cdkeys_len} total: {total}")
            
                if cdkeys_len == 0:
                    logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: No blindbox")
                    return "ERROR"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_list delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- blindbox_open
                if cdkeys_len==10:
                    blindboxes = await self.blindbox_open_clicker(cdkeys)
                    if blindboxes is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open response: {blindboxes}")
                    box_soul=0
                    box_core=0
                    box_usd=0
                    box_ticket=0
                    for blindbox in blindboxes:
                        box_soul   += blindbox['soul']
                        box_core   += blindbox['core']
                        box_usd    += blindbox['usd']
                        box_ticket += blindbox['ticket']
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} count: {cdkeys_len}/{total} soul: {box_soul} core: {box_core} ticket: {box_ticket} usd: {round(box_usd,2)}")
                else:
                    i=0
                    for cdkey in cdkeys:
                        i+=1
                        blindboxes = await self.blindbox_open_clicker([cdkey])
                        if blindboxes is None:
                            return "ERROR"
                        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} blindbox_open response: {blindboxes}")
                        box_soul=0
                        box_core=0
                        box_usd=0
                        box_ticket=0
                        for blindbox in blindboxes:
                            box_soul   += blindbox['soul']
                            box_core   += blindbox['core']
                            box_usd    += blindbox['usd']
                            box_ticket += blindbox['ticket']
                        logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} count: {i}/{cdkeys_len} soul: {box_soul} core: {box_core} ticket: {box_ticket} usd: {round(box_usd,2)}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} count: {i}/{cdkeys_len} soul: {box_soul} core: {box_core} ticket: {box_ticket} usd: {round(box_usd,2)}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_openblindbox except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_buytickets(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
    
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # # -------------------------------------------------------------------------- ticket_level
            tick_level=os.environ.get('TICKET_LEVEL', '0')
            if tick_level == '0':
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: Please set TICKET_LEVEL")
                return "ERROR"
            tick_level=int(tick_level)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} tick_level: {tick_level}")
            
            # -------------------------------------------------------------------------- ticketgenerate
            clicker_response = await self.ticket_generate_clicker(tick_level)
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketgenerate response: {clicker_response}")  # {'level': 1, 'percentage': 90, 'final_hash': 'xxxxxxx'}
            
            tick_rebate = clicker_response['percentage']
            final_hash = clicker_response['final_hash']
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} tick_level: {tick_level} tick_rebate: {tick_rebate} final_hash: {final_hash}")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_generate delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- ticket_buy
            blindboxes = await self.ticket_buy_clicker(tick_level,tick_rebate,final_hash)
            if blindboxes is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_buy response: {blindboxes}")
            
            delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # ticket_buy
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_buy delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Ticket purchase successfully")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_buytickets except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_buygodhoodid(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            if len(REFERRAL_ADDRESS) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} REFERRAL_ADDRESS is Null")
                raise Exception("REFERRAL_ADDRESS is Null")
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # godhoodid
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # # -------------------------------------------------------------------------- bindaddress
            # if eth_address is None or eth_address == "":
            #     clicker_response = await self.bind_address_clicker()
            #     if clicker_response is None:
            #         return "ERROR"
            #     logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} bindaddress response: {clicker_response}")
            
            # -------------------------------------------------------------------------- 5 godhoodid_buy
            clicker_response = await self.godhoodid_buy_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid_buy response: {clicker_response}")

            delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # buygodhoodid - inviter
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodid_buy delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} GodhoodID purchase successfully")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_buygodhoodid except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodemotion(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # godhoodreward
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- godhoodinfo
            clicker_response = await self.godhoodinfo_clicker() # mood
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
            
            if clicker_response['mood']:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotion_code: {clicker_response['mood']['emotion_code']}")
                return "SUCCESS"
            
            # -------------------------------------------------------------------------- godhoodemotion
            clicker_response = await self.godhoodemotion_clicker(eth_address)
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodemotion response: {clicker_response}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodemotion except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodinfo(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- godhoodinfo
            clicker_response = await self.godhoodinfo_clicker() # mood
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
            
            if clicker_response['mood']:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotion_code: {clicker_response['mood']['emotion_code']}")
                return "SUCCESS"
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotion_code: None")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodinfo except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodgrowthinfo(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- godhoodgrowthinfo
            clicker_response = await self.godhoodgrowthinfo_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodgrowthinfo response: {clicker_response}")
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} growthinfo: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodgrowthinfo except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodtransfer(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # godhoodreward
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- godhoodinfo blindbox_usd
            clicker_response = await self.godhoodinfo_clicker() # blindbox_usd
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
            
            if clicker_response['mood'] is None:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: Please mint GODHOOD ID first")
                return "ERROR"
            blindbox_usd = clicker_response['godhood']['blindbox_usd']
            if blindbox_usd == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: No transfer required")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- godhoodtransfer
            clicker_response = await self.godhoodtransfer_clicker(eth_address)
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer response: {clicker_response} - blindbox_usd: {blindbox_usd}")
            
            delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # godhoodtransfer
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodtransfer delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} {clicker_response} - blindbox_usd: {blindbox_usd}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodtransfer except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodreward(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # godhoodreward
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- godhoodreward
            clicker_response = await self.godhoodreward_clicker(eth_address)
            if clicker_response is None or str(clicker_response).find("ERROR") > -1:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodreward response: {clicker_response}")
            
            if clicker_response < 10.0: # 余额大于10USDC显示绿色
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            else:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodreward except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_godhoodclaimed(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # godhoodclaimed
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- godhoodclaimed
            clicker_response = await self.godhoodclaimed_clicker(eth_address)
            if clicker_response is None or str(clicker_response).find("ERROR") > -1:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodclaimed response: {clicker_response}")
            
            delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # godhoodclaimed
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodclaimed delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Godhood claimed successful")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_godhoodclaimed except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_emotionreward(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # emotionreward
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- emotionreward
            clicker_response = await self.emotionreward_clicker(eth_address)
            if clicker_response is None or str(clicker_response).find("ERROR") > -1:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionreward response: {clicker_response}")
            
            if clicker_response < 5.0: # 余额大于5USDC显示绿色
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            else:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_emotionreward except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_emotionclaimed(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # emotionclaimed
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- emotionclaimed
            clicker_response = await self.emotionclaimed_clicker(eth_address)
            if clicker_response is None or str(clicker_response).find("ERROR") > -1:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionclaimed response: {clicker_response}")
            
            delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # emotionclaimed
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionclaimed delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Emotion claimed successful")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_emotionclaimed except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_choicereward(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # choicereward
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- choicereward
            clicker_response = await self.choicereward_clicker(eth_address)
            if clicker_response is None or str(clicker_response).find("ERROR") > -1:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choicereward response: {clicker_response}")
            
            if clicker_response < 5.0: # 余额大于5USDC显示绿色
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            else:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_choicereward except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_choiceclaimed(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # choiceclaimed
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- choiceclaimed
            clicker_response = await self.choiceclaimed_clicker(eth_address)
            if clicker_response is None or str(clicker_response).find("ERROR") > -1:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceclaimed response: {clicker_response}")
            
            delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # choiceclaimed
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceclaimed delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Choice claimed successful")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_choiceclaimed except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_snftmint(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # snftmint
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- generate
            clicker_response = await self.snft_generate_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftgenerate response: {clicker_response}")  # {'nft_score': 19880, 'nft_level': 4, 'nft_role': 'Soul Genesis IV'}
            current_level = clicker_response['nft_level']
            if current_level == 0: # 无效等级
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} current_level: {current_level} | Insufficient level.")
                return "ERROR"
            elif current_level == 4:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} current_level: {current_level} | Maximum level.")
                return "SUCCESS"
            
            # -------------------------------------------------------------------------- snftmint
            nftlevel = await self.snft_ismint_clicker(eth_address)
            if nftlevel == 4: # 已铸造,最大等级,不可升级
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} nftlevel: {nftlevel} | No need to upgrade to the maximum level.")
                return "SUCCESS"
            elif nftlevel == current_level: # 已铸造,无效升级
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} nftlevel: {nftlevel} | No need to upgrade if at the same level.")
                return "SUCCESS"
            elif nftlevel==0 or (nftlevel>0 and nftlevel < current_level): # 可铸造 or 已铸造,可升级
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} nftlevel: {nftlevel} | Upgrade to the next level.")
                # -------------------------------------------------------------------------- generate
                clicker_response = await self.snft_generate_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftgenerate response: {clicker_response}")  # {'nft_level': 3, 'block_number': 33203269, 'final_hash': '0x46fcb058ce'}
                if len(self.client.prikey) in [64,66]:
                    nft_level = clicker_response['nft_level']
                    block_number = clicker_response['block_number']
                    final_hash = clicker_response['final_hash']
                    # -------------------------------------------------------------------------- snftmint
                    await self.snftmint_clicker(eth_address, nft_level,block_number,final_hash)

                    delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # snftmint
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftmint delay: {delay} seconds")
                    await asyncio.sleep(delay)
                return "SUCCESS"
            else:
                raise Exception("nftlevel error")
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_snftmint except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_snftinfo(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # snftinfo
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- snftmint
            nftlevel = await self.snft_ismint_clicker(eth_address)
            if nftlevel is None:
                return "ERROR"
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} nftlevel: {nftlevel}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_snftinfo except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_snftoblate(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # snftoblate
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- snftlist
            clicker_response = await self.snftlist_clicker()
            if clicker_response is None:
                return "ERROR"
            
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftlist response: {clicker_response}")
            if clicker_response['claimed']==1:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snft oblate already completed")
                return "SUCCESS"
            else:
                tokens = clicker_response['tokens']
                tokenids = []
                for token in tokens:
                    if token['status']==0:
                        tokenids.append(token['id'])
                logger.debug(f"tokenids: {tokenids}")
                if len(tokenids)==0:
                    logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The snft tokens are empty, Unable to complete.")
                else:
                    # -------------------------------------------------------------------------- snftoblate
                    clicker_response = await self.snftoblate_clicker(tokenids)
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate response: {clicker_response}")

                    delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # snftoblate
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} snftoblate delay: {delay} seconds")
                    await asyncio.sleep(delay)
                
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} {clicker_response}")
                return "SUCCESS"
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_snftoblate except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_anftmint(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # anftmint
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- generate
            clicker_response = await self.anft_generate_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftgenerate response: {clicker_response}")  # {'nft_score': 19880, 'nft_ticket': 4, 'nft_role': 'Soul Genesis IV'}
            current_ticket = clicker_response['nft_ticket']
            if current_ticket == 0: # 无效等级
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} current_ticket: {current_ticket} | Insufficient ticket.")
                return "ERROR"
            
            # -------------------------------------------------------------------------- anftmint
            nftticket = await self.anft_ismint_clicker(eth_address)
            if nftticket == current_ticket: # 已铸造,无效升级
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} nftticket: {nftticket} | No need to upgrade if at the same ticket.")
                return "SUCCESS"
            elif nftticket==0 or (nftticket>0 and nftticket < current_ticket): # 可铸造 or 已铸造,可升级
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} nftticket: {nftticket} | Upgrade to the next ticket.")
                # -------------------------------------------------------------------------- generate
                clicker_response = await self.anft_generate_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftgenerate response: {clicker_response}")  # {'nft_ticket': 3, 'block_number': 33203269, 'final_hash': '0x46fcb058ce'}
                if len(self.client.prikey) in [64,66]:
                    nft_ticket = clicker_response['nft_ticket']
                    block_number = clicker_response['block_number']
                    final_hash = clicker_response['final_hash']
                    # -------------------------------------------------------------------------- anftmint
                    await self.anftmint_clicker(eth_address, nft_ticket,block_number,final_hash)

                    delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # anftmint
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftmint delay: {delay} seconds")
                    await asyncio.sleep(delay)
            else:
                raise Exception("nftticket error")
            
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_anftmint except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_anftinfo(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # anftinfo
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- anftmint
            nftticket = await self.anft_ismint_clicker(eth_address)
            if nftticket is None:
                return "ERROR"
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} nftticket: {nftticket}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_anftinfo except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_anftoblate(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # anftoblate
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- anftlist
            clicker_response = await self.anftlist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftlist response: {clicker_response}")
            
            if clicker_response['claimed']==1:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anft oblate already completed")
                return "SUCCESS"
            else:
                tokens = clicker_response['tokens']
                tokenids = []
                for token in tokens:
                    if token['status']==0:
                        tokenids.append(token['id'])
                logger.debug(f"tokenids: {tokenids}")
                if len(tokenids)==0:
                    logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} The anft tokens are empty, Unable to complete.")
                else:
                    # -------------------------------------------------------------------------- anftoblate
                    clicker_response = await self.anftoblate_clicker(tokenids)
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate response: {clicker_response}")
                
                    delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # anftoblate
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} anftoblate delay: {delay} seconds")
                    await asyncio.sleep(delay)
                    
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} {clicker_response}")
                return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_anftoblate except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_mission(self, type=1):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # mission
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- missionlist
            clicker_response = await self.missionlist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionlist response: {clicker_response}")
            
            for mission in clicker_response:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} mission: {mission}")
                mission_id = int(mission['id'])
                if mission['status'] == 0 and type == 1:  # 0 - 未开始 / 1 - 可领取 / 2 - 已结束
                    if not (10 < mission_id < 99 or 110 < mission_id < 199):
                        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} mission id: {mission_id} skiped")
                        continue
                    # -------------------------------------------------------------------------- missionconnect
                    clicker_response = await self.missionconnect_clicker(mission_id)
                    if clicker_response is None:
                        return "ERROR"
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect response: {clicker_response} - mission: {mission_id}")
                    
                    delay = random.randint(10, 20)
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missionconnect delay: {delay} seconds")
                    await asyncio.sleep(delay)
                elif mission['status'] == 1 and type == 2:  # 0 - 未开始 / 1 - 可领取 / 2 - 已结束
                    # -------------------------------------------------------------------------- missioncomplete
                    clicker_response = await self.missioncomplete_clicker(mission_id)
                    if clicker_response is None:
                        return "ERROR"
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete response: {clicker_response} - mission: {mission_id}")

                    delay = random.randint(10, 20)
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} missioncomplete delay: {delay} seconds")
                    await asyncio.sleep(delay)
                
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} mission task completed")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_mission except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_milestoneburn(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # milestoneburn
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- milestonelist
            clicker_response = await self.milestonelist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist response: {clicker_response}")
            
            ticket_burn=int(os.environ.get('TASK_TICKET', '0'))
            ticket_burn_random=int(os.environ.get('TASK_TICKET_RANDOM', '0'))
            ticket_burn = ticket_burn + random.randint(0, ticket_burn_random)
            for milestone in clicker_response:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestone: {milestone}")
                milestone_id = int(milestone['id'])
                if milestone['status'] == 2:  # 1 - 未开始 / 2 - 进行中 / 3 - 已结束
                    burn_user = milestone.get('burn_user', 0)
                    burn_max = milestone.get('burn_max', 200)
                    # --------------------------------------------------------------------------
                    if ticket_burn <= burn_user:
                        logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Burning is complete. - {burn_user}/{burn_max}")
                    elif burn_max <= burn_user:
                        logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Burning is maximum. - {burn_user}/{burn_max}")
                    else:
                        burn_real = ticket_burn - burn_user
                        # -------------------------------------------------------------------------- milestoneburn
                        clicker_response = await self.milestoneburn_clicker(milestone_id, burn_real)
                        if clicker_response is None:
                            return "ERROR"
                        logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneburn response: {clicker_response} - milestone: {milestone_id} burn: {burn_real}")
            
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Milestone burn completed")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_milestoneburn except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_milestoneclaim(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # milestoneclaim
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- milestonelist
            clicker_response = await self.milestonelist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestonelist response: {clicker_response}")
            
            for milestone in clicker_response:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestone: {milestone}")
                milestone_id = int(milestone['id'])
                if milestone['claim_box'] == 1:
                    # -------------------------------------------------------------------------- milestoneclaim
                    clicker_response = await self.milestoneclaim_clicker(milestone_id, 1)
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim response: {clicker_response} - claim_box: {milestone_id}")
                if milestone['claim_sxp'] == 1:
                    # -------------------------------------------------------------------------- milestoneclaim
                    clicker_response = await self.milestoneclaim_clicker(milestone_id, 2)
                    if clicker_response is None:
                        return "ERROR"
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim response: {clicker_response} - claim_sxp: {milestone_id}")
                    
                    delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # milestoneclaim
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} milestoneclaim delay: {delay} seconds")
                    await asyncio.sleep(delay)
            
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Milestone claimed completed")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_milestoneclaim except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_visionburn(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # visionburn
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- visionlist
            clicker_response = await self.visionlist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist response: {clicker_response}")
            
            for vision in clicker_response:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} vision: {vision}")
                vision_id = int(vision['id'])
                if vision['status'] == 1:  # 0 - 未开始 / 1 - 进行中 / 2 - 已结束
                    burn_user = vision.get('burn_user', 0)
                    burn_max = vision.get('ticket_limit', 200)
                    # --------------------------------------------------------------------------
                    if burn_max <= burn_user:
                        logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Burning is maximum. - {burn_user}/{burn_max}")
                    else:
                        # -------------------------------------------------------------------------- ticketbox_list
                        ticket_response = await self.ticketbox_list_clicker()
                        if ticket_response is None:
                            return "ERROR"
                        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list response: {ticket_response}")
                        
                        cdkeys = ticket_response.get("cdkeys", [])
                        if len(cdkeys) == 0:
                            logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} No ticket")
                            return "ERROR"
                        
                        delay = random.randint(10, 20)
                        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list delay: {delay} seconds")
                        await asyncio.sleep(delay)
                        
                        # -------------------------------------------------------------------------- visionburn
                        burn_attempts = min(burn_max-burn_user, len(cdkeys))
                        for i in range(burn_attempts):
                            try:
                                clicker_response = await self.visionburn_clicker(vision_id, cdkeys[i])
                                if clicker_response is None:
                                    continue
                                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn response: {clicker_response} - vision: {vision_id} burn: {cdkeys[i]} - {burn_user+i+1}/{burn_user+burn_attempts}")
                            except Exception as e:
                                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ERROR: {str(e)}")
                                # 继续执行下一个任务而不是中断整个流程
                                continue
                            
                            delay = random.randint(60, 90) # visionburn
                            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionburn delay: {delay} seconds")
                            await asyncio.sleep(delay)
            
            logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Vision burn completed")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_visionburn except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_visionclaim(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # visionclaim
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- visionlist
            clicker_response = await self.visionlist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionlist response: {clicker_response}")
            
            for vision in clicker_response:
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} vision: {vision}")
                vision_id = int(vision['id'])
                # -------------------------------------------------------------------------- visionclaim
                clicker_response = await self.visionclaim_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim response: {clicker_response} - vision_id: {vision_id}")

                delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # visionclaim
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} visionclaim delay: {delay} seconds")
                await asyncio.sleep(delay)
            
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Vision claimed completed")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_visionclaim except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_fundsreward(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            if len(json.loads(POOLING_ADDRESS)) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} POOLING_ADDRESS is Null")
                raise Exception("POOLING_ADDRESS is Null")
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # fundsreward
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- fundsreward
            clicker_response = await self.fundsreward_clicker(eth_address)
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} fundsreward response: {clicker_response}")
            
            if clicker_response < 5.0: # 余额大于5USDC显示绿色
                logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            else:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} | eth_address: {eth_address[:10]} balance: {clicker_response}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_fundsreward except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_fundspooling(self, is_all=False):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            if len(json.loads(POOLING_ADDRESS)) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} POOLING_ADDRESS is Null")
                raise Exception("POOLING_ADDRESS is Null")
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # fundspooling
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # -------------------------------------------------------------------------- fundspooling
            clicker_response = await self.fundspooling_clicker(eth_address, is_all)
            if clicker_response is None:
                return "ERROR"
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} fundspooling response: {clicker_response}")

            # if clicker_response>0:
            #     delay = random.randint(SNAIL_UNIT, SNAIL_UNIT*4) # fundspooling
            #     logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} fundspooling delay: {delay} seconds")
            #     await asyncio.sleep(delay)
            delay = random.randint(60, 90) # fundspooling
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} fundspooling delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_fundspooling except: {error}")
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
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist response: {clicker_response}")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            if clicker_response['today'] == 1:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Daily checkin already completed")
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
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin response: {clicker_response}")
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
            clicker_response = await self.session_clicker() # medalcheckin
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} - medal: {clicker_response['medal']} medal_expired: {((clicker_response['medal_expired']-int(time.time()))/60/60/24 if clicker_response['medal'] else 0):.2f} days")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # --------------------------------------------------------------------------
            if clicker_response['medal']:
                # -------------------------------------------------------------------------- 2 medalcheckin
                clicker_response = await self.medalcheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin response: {clicker_response}")
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
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist response: {clicker_response}")
            
            if len(clicker_response['today']) > 0:
                emotion_detail = clicker_response['today']
                emotion = emotion_detail.split('_')[0]
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} AITrain already completed")
                # return "SUCCESS"
            else:
                # -------------------------------------------------------------------------- godhoodinfo is_godhood_id
                clicker_response = await self.godhoodinfo_clicker() # is_godhood_id
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")

                is_godhood_id = "1" if clicker_response['mood'] else "0"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 3 aitrain
                emotion=os.environ.get('CHOOSE_EMOTION', '0')
                if emotion == '0':
                    emotion = random.choice(["1", "2", "3"])
                elif emotion == '9':
                    # -------------------------------------------------------------------------- emotionperiod
                    clicker_response = await self.emotionperiod_clicker()
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod response: {clicker_response}")
                    
                    period_id = int(clicker_response.get('id', 0))
                    if period_id == 0:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod period_id: {period_id}")
                    emotion = get_emotion_for_txt(period_id)
                    if emotion == '0' or emotion == '':
                        return "ERROR"
                    os.environ['CHOOSE_EMOTION'] = emotion
                emotion_detail=emotion+'_1_'+is_godhood_id
                clicker_response = await self.aitrain_clicker(emotion_detail)
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain response: {clicker_response}")

                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} AITrain successfully! - emotion: {emotion_detail}")
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_aitrain except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_traincheckin(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            today = time.strftime("%d/%m/%Y", time.localtime())
            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist response: {clicker_response}")
            
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
                    today_complete = item.get('status', 0)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist: {ailist} today_complete: {today_complete}")
            if today_complete == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please complete the deeptraining first")
                return "ERROR"
            elif today_complete == 2:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} DeepTrain checkin already completed")
                return "SUCCESS"
            elif today_complete == 3:
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 4 traincheckin
                clicker_response = await self.traincheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin response: {clicker_response}")
                return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_traincheckin except: {error}")
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
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # deeptrain
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist response: {clicker_response}")
            
            if len(clicker_response['today']) > 0:
                emotion_detail = clicker_response['today']
                emotion = emotion_detail.split('_')[0]
            else:
                # -------------------------------------------------------------------------- godhoodinfo is_godhood_id
                clicker_response = await self.godhoodinfo_clicker() # is_godhood_id
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
                
                is_godhood_id = "1" if clicker_response['mood'] else "0"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 3 aitrain
                emotion=os.environ.get('CHOOSE_EMOTION', '0')
                if emotion == '0':
                    emotion = random.choice(["1", "2", "3"])
                elif emotion == '9':
                    # -------------------------------------------------------------------------- emotionperiod
                    clicker_response = await self.emotionperiod_clicker()
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod response: {clicker_response}")
                    
                    period_id = int(clicker_response.get('id', 0))
                    if period_id == 0:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod period_id: {period_id}")
                    emotion = get_emotion_for_txt(period_id)
                    if emotion == '0' or emotion == '':
                        return "ERROR"
                    os.environ['CHOOSE_EMOTION'] = emotion
                emotion_detail=emotion+'_1_'+is_godhood_id
                clicker_response = await self.aitrain_clicker(emotion_detail)
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain response: {clicker_response}")
                # return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain emotion: {emotion_detail}")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- isdeeptrain
            clicker_response = await self.is_deeptrain_clicker(eth_address)
            if clicker_response is False:
                # -------------------------------------------------------------------------- 5 deeptrain
                await self.deeptrain_clicker(emotion_detail, eth_address)
                
                delay = random.randint(60, 90) # deeptrain
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 5 deeptrain delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- traincheckin
                clicker_response = await self.traincheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin response: {clicker_response}")
                
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_deeptrain except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_tickettrain(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # tickettrain
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- ailist
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist response: {clicker_response}")
            
            if len(clicker_response['today']) > 0:
                emotion_detail = clicker_response['today']
                emotion = emotion_detail.split('_')[0]
            else:
                # -------------------------------------------------------------------------- godhoodinfo is_godhood_id
                clicker_response = await self.godhoodinfo_clicker() # is_godhood_id
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
                
                is_godhood_id = "1" if clicker_response['mood'] else "0"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 3 aitrain
                emotion=os.environ.get('CHOOSE_EMOTION', '0')
                if emotion == '0':
                    emotion = random.choice(["1", "2", "3"])
                elif emotion == '9':
                    # -------------------------------------------------------------------------- emotionperiod
                    clicker_response = await self.emotionperiod_clicker()
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod response: {clicker_response}")
                    
                    period_id = int(clicker_response.get('id', 0))
                    if period_id == 0:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod period_id: {period_id}")
                    emotion = get_emotion_for_txt(period_id)
                    if emotion == '0' or emotion == '':
                        return "ERROR"
                    os.environ['CHOOSE_EMOTION'] = emotion
                emotion_detail=emotion+'_1_'+is_godhood_id
                clicker_response = await self.aitrain_clicker(emotion_detail)
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain response: {clicker_response}")
                # return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain emotion: {emotion_detail}")
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- isdeeptrain
            clicker_response = await self.is_deeptrain_clicker(eth_address)
            if clicker_response is False:
                # -------------------------------------------------------------------------- ticketbox_list
                ticket_response = await self.ticketbox_list_clicker()
                if ticket_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list response: {ticket_response}")
                
                cdkeys = ticket_response.get("cdkeys", [])
                if len(cdkeys) == 0:
                    logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} No ticket")
                    return "ERROR"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- ticket_deeptrain
                clicker_response = await self.ticket_deeptrain_clicker(cdkeys[0], emotion_detail)
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} tickettrain response: {clicker_response}")

                delay = random.randint(60, 90) # ticket_deeptrain
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 5 ticket_deeptrain delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- traincheckin
                clicker_response = await self.traincheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin response: {clicker_response}")
                
                await asyncio.sleep(delay)
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_tickettrain except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_deepchoice(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            if len(self.client.prikey) not in [64,66]:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Incorrect private key")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # deepchoice
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- isdeepchoice
            clicker_response = await self.is_deepchoice_clicker(eth_address)
            if clicker_response is False:
                # -------------------------------------------------------------------------- godhoodinfo is_godhood_id
                clicker_response = await self.godhoodinfo_clicker() # is_godhood_id
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
                
                is_godhood_id = "1" if clicker_response['mood'] else "0"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 
                choice=os.environ.get('CHOOSE_CHOICE', '0')
                if choice == '0':
                    # choice = random.choice(["1", "2", "3", "4"])
                    options = await self.deepchoice_list_clicker()
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_deepchoice options: {options}")
                    choice = random.choice(options)
                elif choice == '9':
                    # -------------------------------------------------------------------------- choiceperiod
                    clicker_response = await self.choiceperiod_clicker()
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod response: {clicker_response}")
                    
                    period_id = int(clicker_response.get('id', 0))
                    if period_id == 0:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod period_id: {period_id}")
                    choice = get_choice_for_txt(period_id)
                    if choice == '0' or choice == '':
                        return "ERROR"
                    os.environ['CHOOSE_CHOICE'] = choice
                vote_soul=random.randint(60, 180)
                choice_detail=f"{choice}_{vote_soul}_{is_godhood_id}"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choice_detail: {choice_detail}")
                # -------------------------------------------------------------------------- 5 deepchoice
                await self.deepchoice_clicker(choice_detail, eth_address)

            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_deepchoice except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_ticketchoice(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # ticketchoice
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            if eth_address is None or eth_address == "":
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- 5 tickettrain
            clicker_response = await self.is_deepchoice_clicker(eth_address)
            if clicker_response is False:
                # -------------------------------------------------------------------------- ticketbox_list
                ticket_response = await self.ticketbox_list_clicker()
                if ticket_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list response: {ticket_response}")
                
                cdkeys = ticket_response.get("cdkeys", [])
                if len(cdkeys) == 0:
                    logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} No ticket")
                    return "ERROR"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- godhoodinfo is_godhood_id
                clicker_response = await self.godhoodinfo_clicker() # is_godhood_id
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
                
                is_godhood_id = "1" if clicker_response['mood'] else "0"
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
                await asyncio.sleep(delay)
                # -------------------------------------------------------------------------- 
                choice=os.environ.get('CHOOSE_CHOICE', '0')
                if choice == '0':
                    # choice = random.choice(["1", "2", "3", "4"])
                    options = await self.deepchoice_list_clicker()
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticket_deepchoice_clicker options: {options}")
                    choice = random.choice(options)
                elif choice == '9':
                    # -------------------------------------------------------------------------- choiceperiod
                    clicker_response = await self.choiceperiod_clicker()
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod response: {clicker_response}")
                    
                    period_id = int(clicker_response.get('id', 0))
                    if period_id == 0:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod period_id: {period_id}")
                    choice = get_choice_for_txt(period_id)
                    if choice == '0' or choice == '':
                        return "ERROR"
                    os.environ['CHOOSE_CHOICE'] = choice
                vote_soul=random.randint(60, 180)
                choice_detail=f"{choice}_{vote_soul}_{is_godhood_id}"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choice_detail: {choice_detail}")
            
                # -------------------------------------------------------------------------- ticket_deepchoice
                clicker_response = await self.ticket_deepchoice_clicker(cdkeys[0], choice_detail)
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketchoice response: {clicker_response}")

                delay = random.randint(60, 90) # ticket_deepchoice
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 5 ticket_deepchoice delay: {delay} seconds")
                await asyncio.sleep(delay)
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_ticketchoice except: {error}")
            return f"ERROR: {error}"

    @helper
    async def daily_clicker_alltask(self):
        try:
            if len(self.client.token) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Not login")
                return "ERROR"
            
            # -------------------------------------------------------------------------- dailylist
            clicker_response = await self.dailylist_clicker()
            if clicker_response is None:
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailylist delay: {delay} seconds")
            await asyncio.sleep(delay)
            
            # --------------------------------------------------------------------------
            if clicker_response['today'] == 1:
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Daily checkin already completed")
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
                clicker_response = await self.dailycheckin_clicker(daily)
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} dailycheckin response: {clicker_response}")

                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 1 dailycheckin_clicker delay: {delay} seconds")
                await asyncio.sleep(delay)


            # -------------------------------------------------------------------------- session
            clicker_response = await self.session_clicker() # alltask
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} session response: {clicker_response}")
            
            eth_address = clicker_response['eth_address']
            # if eth_address is None or eth_address == "":
            #     logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
            #     return "ERROR"

            # -------------------------------------------------------------------------- medalcheckin
            logger.info(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medal: {clicker_response['medal']} medal_expired: {((clicker_response['medal_expired']-int(time.time()))/60/60/24 if clicker_response['medal'] else 0):.2f} days")
            delay = random.randint(10, 20)
            await asyncio.sleep(delay)

            if clicker_response['medal']:
                # -------------------------------------------------------------------------- 2 medalcheckin
                clicker_response = await self.medalcheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} medalcheckin response: {clicker_response}")

                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 2 medalcheckin delay: {delay} seconds")
                await asyncio.sleep(delay)

            task=os.environ.get('TASK_EMOTION', '0')
            if task == '0':  # no aitrain
                return "SUCCESS"
            
            # -------------------------------------------------------------------------- godhoodinfo is_godhood_id
            clicker_response = await self.godhoodinfo_clicker() # is_godhood_id
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo response: {clicker_response['mood']}")
            
            is_godhood_id = "1" if clicker_response['mood'] else "0"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} godhoodinfo delay: {delay} seconds")
            await asyncio.sleep(delay)
            # -------------------------------------------------------------------------- ailist aitrain
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist response: {clicker_response}")
            
            if len(clicker_response['today']) > 0:
                emotion_detail = clicker_response['today']
                emotion = emotion_detail.split('_')[0]
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} AITrain already completed")
                # return "SUCCESS"
            else:
                # -------------------------------------------------------------------------- 3 aitrain
                emotion=os.environ.get('CHOOSE_EMOTION', '0')
                if emotion == '0':
                    emotion = random.choice(["1", "2", "3"])
                elif emotion == '9':
                    # -------------------------------------------------------------------------- emotionperiod
                    clicker_response = await self.emotionperiod_clicker()
                    if clicker_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod response: {clicker_response}")
                    
                    period_id = int(clicker_response.get('id', 0))
                    if period_id == 0:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} emotionperiod period_id: {period_id}")
                    emotion = get_emotion_for_txt(period_id)
                    if emotion == '0' or emotion == '':
                        return "ERROR"
                    # os.environ['CHOOSE_EMOTION'] = emotion
                emotion_detail=emotion+'_1_'+is_godhood_id
                clicker_response = await self.aitrain_clicker(emotion_detail)
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} aitrain response: {clicker_response}")

                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 3 aitrain delay: {delay} seconds")
                await asyncio.sleep(delay)
            
            if eth_address is None or eth_address == "":
                # logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please bind the eth_address first")
                return "ERROR"
            
            # -------------------------------------------------------------------------- deeptrain
            clicker_response = await self.is_deeptrain_clicker(eth_address)
            if clicker_response is False:
                task=os.environ.get('TASK_EMOTION', '0')
                if task == '1':  # no train
                    return "SUCCESS"
                elif task == '2':  # deeptrain
                    # -------------------------------------------------------------------------- 4 deeptrain
                    if len(self.client.prikey) in [64,66]:
                        await self.deeptrain_clicker(emotion_detail, eth_address)

                        delay = random.randint(60, 90) # deeptrain
                        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 4 deeptrain delay: {delay} seconds")
                        await asyncio.sleep(delay)
                elif task == '3':  # tickettrain
                    # -------------------------------------------------------------------------- ticketbox_list
                    ticket_response = await self.ticketbox_list_clicker()
                    if ticket_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list response: {ticket_response}")

                    cdkeys = ticket_response.get("cdkeys", [])
                    if len(cdkeys) == 0:
                        logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} No ticket")
                        return "ERROR"
                    
                    delay = random.randint(10, 20)
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list delay: {delay} seconds")
                    await asyncio.sleep(delay)
                    # -------------------------------------------------------------------------- ticket_deeptrain
                    clicker_response = await self.ticket_deeptrain_clicker(cdkeys[0], emotion_detail)
                    if clicker_response is None:
                        return "ERROR"
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} tickettrain response: {clicker_response}")
                    
                    delay = random.randint(60, 90) # ticket_deeptrain
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 5 ticket_deeptrain delay: {delay} seconds")
                    await asyncio.sleep(delay)
            
            today = time.strftime("%d/%m/%Y", time.localtime())
            # -------------------------------------------------------------------------- ailist traincheckin
            clicker_response = await self.ailist_clicker()
            if clicker_response is None:
                return "ERROR"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist response: {clicker_response}")
            
            if len(clicker_response['today']) == 0:
                logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} Please complete the aitraining first")
                return "ERROR"
            
            delay = random.randint(10, 20)
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ailist delay: {delay} seconds")
            await asyncio.sleep(delay)
            # --------------------------------------------------------------------------
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
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} DeepTrain checkin already completed")
                # return "SUCCESS"
            else:
                # -------------------------------------------------------------------------- 5 traincheckin
                clicker_response = await self.traincheckin_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin response: {clicker_response}")
                
                delay = random.randint(10, 20)
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} traincheckin delay: {delay} seconds")
                await asyncio.sleep(delay)
            
            # --------------------------------------------------------------------------
            choice=os.environ.get('CHOOSE_CHOICE', '0')
            if choice == '0':
                # choice = random.choice(["1", "2", "3", "4"])
                options = await self.deepchoice_list_clicker()
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_deepchoice options: {options}")
                choice = random.choice(options)
            elif choice == '9':
                # -------------------------------------------------------------------------- choiceperiod
                clicker_response = await self.choiceperiod_clicker()
                if clicker_response is None:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod response: {clicker_response}")
                
                period_id = int(clicker_response.get('id', 0))
                if period_id == 0:
                    return "ERROR"
                logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choiceperiod period_id: {period_id}")
                choice = get_choice_for_txt(period_id)
                if choice == '0' or choice == '':
                    return "ERROR"
                # os.environ['CHOOSE_CHOICE'] = choice
            vote_soul=random.randint(60, 180)
            choice_detail=f"{choice}_{vote_soul}_{is_godhood_id}"
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} choice_detail: {choice_detail}")
            # -------------------------------------------------------------------------- deepchoice
            clicker_response = await self.is_deepchoice_clicker(eth_address)
            if clicker_response is False:
                task=os.environ.get('TASK_CHOICE', '0')
                if task == '0':  # no choice
                    return "SUCCESS"
                elif task == '1':  # deepchoice
                    # -------------------------------------------------------------------------- 4 deepchoice
                    if len(self.client.prikey) in [64,66]:
                        await self.deepchoice_clicker(choice_detail, eth_address)

                        delay = random.randint(60, 90) # deepchoice
                        logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 4 deepchoice delay: {delay} seconds")
                        await asyncio.sleep(delay)
                elif task == '2':  # ticketchoice
                    # -------------------------------------------------------------------------- ticketbox_list
                    ticket_response = await self.ticketbox_list_clicker()
                    if ticket_response is None:
                        return "ERROR"
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list response: {ticket_response}")

                    cdkeys = ticket_response.get("cdkeys", [])
                    if len(cdkeys) == 0:
                        logger.error(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} No ticket")
                        return "ERROR"
                    
                    delay = random.randint(10, 20)
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketbox_list delay: {delay} seconds")
                    await asyncio.sleep(delay)
                    # -------------------------------------------------------------------------- ticket_deepchoice
                    clicker_response = await self.ticket_deepchoice_clicker(cdkeys[0], choice_detail)
                    if clicker_response is None:
                        return "ERROR"
                    logger.success(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} ticketchoice response: {clicker_response}")
                    
                    delay = random.randint(60, 90) # ticket_deepchoice
                    logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} 5 ticket_deepchoice delay: {delay} seconds")
                    await asyncio.sleep(delay)
            
            return "SUCCESS"
        except Exception as error:
            logger.debug(f"id: {self.client.id} userid: {self.client.userid} email: {self.client.email} daily_clicker_alltask except: {error}")
            return f"ERROR: {error}"
