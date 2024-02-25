import yaml
import logging
import re
import requests
import rsa
import base64
import binascii
import time
from tenacity import retry, stop_after_attempt, wait_random

import notify

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Info:
    def __init__(
            self,
            success: bool,
            username: str,
            message: str,
            reward_notice: str,
            lottery_notice1: str,
            lottery_notice2: str,
            lottery_notice3: str):
        self.success = success
        self.username = username
        self.message = message
        self.reward_notice = reward_notice
        self.lottery_notice1 = lottery_notice1
        self.lottery_notice2 = lottery_notice2
        self.lottery_notice3 = lottery_notice3
        

    def __str__(self) -> str:
        message_all = ''
        if self.success:
            message_all = f'用户：{self.username}\n' \
                          f'奖励：{self.reward_notice}\n' \
                          f'任务1：{self.lottery_notice1}\n' \
                          f'任务2：{self.lottery_notice2}\n' \
                          f'任务3：{self.lottery_notice3}'
                          
        else:
            message_all = f'签到失败\n错误信息：{self.message}'

        return message_all
    
class Cloud:
    """
    天翼云盘签到（自动领取奖励）

    :param username: 天翼云盘账户
    :param password: 天翼云盘密码
    :return Info: 
    """

    def check_in(self, username: str, password: str) -> Info:
        info = Info(
            success=False,
            username=username,
            message='',
            reward_notice='',
            lottery_notice1='',
            lottery_notice2='',
            lottery_notice3=''
        )

        def handle_error(error_message: str) -> Info:
            info.message = error_message
            return info

        def add_message(message: str) -> Info:
            if info.message == "":
                info.message = message
            else:
                info.message += f"；{message}"

        try:
            flag, session, message = self._login(username,password)
            if not flag:
                return handle_error(f"登录出错：{message}")\
                
            flag, message = self._get_reward(session)
            if not flag:
                return handle_error(f"签到出错：{message}")
            else:
                info.reward_notice=message
            
            flag, message = self._task1(session)
            if not flag:
                add_message(message)
            else:
                info.lottery_notice1=message

            flag, message = self._task2(session)
            if not flag:
                add_message(message)
            else:
                info.lottery_notice2=message

            flag, message = self._task3(session)
            if not flag:
                add_message(message)
            else:
                info.lottery_notice3=message
            
            info.success = True
            return info

        except Exception as e:
            return handle_error(f"发生意外错误：{str(e)}")
        
    @retry(stop=stop_after_attempt(10), wait=wait_random(min=10, max=30))
    def _login(self, username: str, password: str) -> tuple[bool, requests.Session, str]:
        urlToken="https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
        session = requests.Session()
        redirect_response = session.get(urlToken)
        if re.search(r"https?://[^\s'\"]+", redirect_response.text):
            url = re.search(r"https?://[^\s'\"]+", redirect_response.text).group()
        else:
            return False, session, "未找到url"
        
        login_response = session.get(url)
        if re.search(r"<a id=\"j-tab-login-link\"[^>]*href=\"([^\"]+)\"", login_response.text):  # 匹配id为j-tab-login-link的a标签
            href_url = re.search(r"<a id=\"j-tab-login-link\"[^>]*href=\"([^\"]+)\"", login_response.text).group(1)  # 获取捕获的内容
        else:
            return False, session, "未找到href_url"
        
        token_response = session.get(href_url)
        captchaToken = re.findall(r"captchaToken' value='(.+?)'", token_response.text)[0]
        lt = re.findall(r'lt = "(.+?)"', token_response.text)[0]
        return_url = re.findall(r"returnUrl= '(.+?)'", token_response.text)[0]
        paramId = re.findall(r'paramId = "(.+?)"', token_response.text)[0]
        j_rsakey = re.findall(r'j_rsaKey" value="(\S+)"', token_response.text, re.M)[0]
        session.headers.update({"lt": lt})

        encode_username = self._rsa_encode(j_rsakey, username)
        encode_password = self._rsa_encode(j_rsakey, password)

        login_url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
            'Referer': 'https://open.e.189.cn/',
        }
        data = {
            "appKey": "cloud",
            "accountType": '01',
            "userName": f"{{RSA}}{encode_username}",
            "password": f"{{RSA}}{encode_password}",
            "validateCode": "",
            "captchaToken": captchaToken,
            "returnUrl": return_url,
            "mailSuffix": "@189.cn",
            "paramId": paramId
        }
        logined_response = session.post(login_url, data=data, headers=headers, timeout=5)
        if (logined_response.json()['result'] == 0):    # 登录成功
            callback_response = session.get(logined_response.json()['toUrl'])
            return True, session, logined_response.json()['msg']
        else:                                           # 登录失败
            return False, session, logined_response.json()['msg']

    def _base64tohex(self, base64_str: str) -> str:
        decoded_bytes = base64.b64decode(base64_str)
        hex_str = binascii.hexlify(decoded_bytes).decode('utf-8')
        return hex_str
        
    def _rsa_encode(self, j_rsakey: str, string: str) -> str:
        rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
        result = self._base64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
        return result

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=10, max=30))
    def _get_reward(self, session: requests.Session) -> tuple[bool, str]:
        rand = str(round(time.time() * 1000))
        surl = f"https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
            "Accept-Encoding": "gzip, deflate",
        }

        try:
            reward_response = session.get(surl, headers=headers)
            netdiskBonus = reward_response.json()['netdiskBonus']
        except Exception as e:
            return False, str(e)
        else:
            if (reward_response.json()['isSign'] == "false"):
                return True, f"未签到，签到获得{netdiskBonus}M空间"
            else:
                return True, f"已经签到过了，签到获得{netdiskBonus}M空间"

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=10, max=30))
    def _task1(self, session: requests.Session) -> tuple[bool, str]:
        task1_url = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
            "Accept-Encoding": "gzip, deflate",
        }
        try:
            task1_response = session.get(task1_url, headers=headers)
        except Exception as e:
            return False, str(e)
        else:
            if ("errorCode" in task1_response.text):
                return True, "抽奖1失败"
            else:
                return True, f"抽奖1成功：抽奖获得{task1_response.json()['description']}"

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=10, max=30))       
    def _task2(self, session: requests.Session) -> tuple[bool, str]:
        task2_url = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
            "Accept-Encoding": "gzip, deflate",
        }
        try:
            task2_response = session.get(task2_url, headers=headers)
        except Exception as e:
            return False, str(e)
        else:
            if ("errorCode" in task2_response.text):
                return True, "抽奖2失败"
            else:
                return True, f"抽奖2成功：抽奖获得{task2_response.json()['description']}"

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=10, max=30))       
    def _task3(self, session: requests.Session) -> tuple[bool, str]:
        task3_url = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
            "Accept-Encoding": "gzip, deflate",
        }
        try:
            task3_response = session.get(task3_url, headers=headers)
        except Exception as e:
            return False, str(e)
        else:
            if ("errorCode" in task3_response.text):
                return True, "抽奖3失败"
            else:
                return True, f"抽奖3成功：抽奖获得{task3_response.json()['description']}"

def main() -> None:
    try:
        with open("./config.yaml", "r", encoding="utf-8") as file:
            config_data = yaml.safe_load(file)["189Cloud"]
    except Exception as e:
        logging.critical(f"天翼云盘配置读取失败{str(e)}")
        return
    else:
        if config_data["enable"]:
            cloud = Cloud()
            content = []
            for index, account in enumerate(config_data["Account_List"]):
                logging.info(f"开始签到第{index + 1}个账户")
                try:
                    username = account["username"]
                    password = account["password"]
                except:
                    logging.warning(f"获取第{index + 1}个账户用户名密码失败")
                else:
                    result = cloud.check_in(username, password)
                    content.append(str(result))

                if index +1 < len(config_data["Account_List"]):
                    content.append("-----")

            logging.info("所有账户签到结束")
            notify.send("天翼云盘已签到",re.sub('\n+', '\n', '\n'.join(content)).rstrip('\n'))
        else:
            logging.info("天翼云盘签到已关闭")
        return

if __name__ == "__main__":
    main()