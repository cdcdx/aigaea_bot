
from src.gaea_client import GaeaClient
from utils.get_capcha_key import TwoCaptcha

async def get_captcha_key(client: GaeaClient):
    two_captcha = TwoCaptcha(client)
    task_id = await two_captcha.create_captcha_task()
    return await two_captcha.getting_captcha_key(task_id=task_id)
