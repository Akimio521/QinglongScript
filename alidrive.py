# -*- coding:utf-8 -*-
import yaml
import logging
import requests
from tenacity import retry, stop_after_attempt, wait_random, RetryError
import re

import notify

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AliyundriveInfo:
    def __init__(
            self,
            success: bool,
            user_name: str,
            signin_count: int,
            message: str,
            reward_notice: str,
            task_notice: str):
        self.success = success
        self.user_name = user_name
        self.signin_count = signin_count
        self.message = message
        self.reward_notice = reward_notice
        self.task_notice = task_notice

    def __str__(self) -> str:
        message_all = ''
        if self.success:
            message_all = f'用户：{self.user_name}\n' \
                          f'签到：本月已签到{self.signin_count}次\n' \
                          f'奖励：{self.reward_notice}\n' \
                          f'任务：{self.task_notice}'

        else:
            message_all = f'签到失败\n错误信息：{self.message}'

        return message_all

class Aliyundrive:
    """
    阿里云盘签到（自动领取奖励）

    :param token: 阿里云盘token
    :return AliyundriveInfo: 
    """

    def aliyundrive_check_in(self, token: str) -> AliyundriveInfo:
        info = AliyundriveInfo(
            success=False,
            user_name='',
            signin_count=-1,
            message='',
            reward_notice='',
            task_notice=''
        )

        def handle_error(error_message: str) -> AliyundriveInfo:
            info.message = error_message
            return info

        try:
            flag, user_name, access_token, message = self._get_access_token(token)
            if not flag:
                return handle_error(f'get_access_token error: {message}')

            flag, signin_count, message = self._check_in(access_token)
            if not flag:
                return handle_error(f'check_in error: {message}')

            flag, message = self._get_reward(access_token, signin_count)
            if not flag:
                return handle_error(f'get_reward error: {message}')

            flag, message, reward_notice, task_notice = self._get_task(access_token)
            if not flag:
                return handle_error(f'get_task error: {message}')

            info.success = True
            info.user_name = user_name
            info.signin_count = signin_count
            info.reward_notice = reward_notice
            info.task_notice = task_notice

            return info

        except RetryError as e:
            return handle_error(f'发生意外错误：{str(e)}')

    """
    获取access_token

    :param token: 阿里云盘token
    :return tuple[0]: 是否成功请求token
    :return tuple[1]: 用户名
    :return tuple[2]: access_token
    :return tuple[3]: message
    """

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=5, max=30))
    def _get_access_token(self, token: str) -> tuple[bool, str, str, str]:
        url = 'https://auth.aliyundrive.com/v2/account/token'
        payload = {'grant_type': 'refresh_token', 'refresh_token': token}

        response = requests.post(url, json=payload, timeout=5)
        data = response.json()

        if 'code' in data and data['code'] in ['RefreshTokenExpired', 'InvalidParameter.RefreshToken']:
            return False, '', '', data['message']

        nick_name, user_name = data['nick_name'], data['user_name']
        name = nick_name if nick_name else user_name
        access_token = data['access_token']
        return True, name, access_token, ''

    """
    执行签到操作

    :param token: 调用_get_access_token方法返回的access_token
    :return tuple[0]: 是否成功
    :return tuple[1]: 签到次数
    :return tuple[2]: message
    """

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=5, max=30))
    def _check_in(self, access_token: str) -> tuple[bool, int, str]:
        url = 'https://member.aliyundrive.com/v1/activity/sign_in_list'
        payload = {'isReward': False}
        params = {'_rx-s': 'mobile'}
        headers = {'Authorization': f'Bearer {access_token}'}

        response = requests.post(url, json=payload, params=params, headers=headers, timeout=5)
        data = response.json()

        if 'success' not in data:
            return False, -1, data['message']

        success = data['success']
        signin_count = data['result']['signInCount']

        return success, signin_count, ''

    """
    获得奖励

    :param token: 调用_get_access_token方法返回的access_token
    :param sign_day: 领取第几天
    :return tuple[0]: 是否成功
    :return tuple[1]: message
    """

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=5, max=30))
    def _get_reward(self, access_token: str, sign_day: int) -> tuple[bool, str]:
        url = 'https://member.aliyundrive.com/v1/activity/sign_in_reward'
        payload = {'signInDay': sign_day}
        params = {'_rx-s': 'mobile'}
        headers = {'Authorization': f'Bearer {access_token}'}

        response = requests.post(url, json=payload, params=params, headers=headers, timeout=5)
        data = response.json()

        if 'result' not in data:
            return False, data['message']

        success = data['success']
        return success, ''

    """
    今日奖励/任务

    :param token: 调用_get_access_token方法返回的access_token
    :return tuple[0]: 是否成功
    :return tuple[1]: message
    :return tuple[2]: 奖励信息
    :return tuple[3]: 任务信息
    """

    @retry(stop=stop_after_attempt(10), wait=wait_random(min=10, max=30))
    def _get_task(self, access_token: str) -> tuple[bool, str]:
        url = 'https://member.aliyundrive.com/v2/activity/sign_in_list'
        payload = {}
        params = {'_rx-s': 'mobile'}
        headers = {'Authorization': f'Bearer {access_token}'}

        response = requests.post(url, json=payload, params=params, headers=headers, timeout=5)
        data = response.json()

        if 'result' not in data:
            return False, data['message']

        success = data['success']
        signInInfos = data['result']['signInInfos']

        day = data['result']['signInCount']
        rewards = filter(lambda info: int(info.get('day', 0)) == day, signInInfos)
        
        award_notice = ''
        task_notice = ''

        for reward in next(rewards)['rewards']:
            name = reward['name']
            remind = reward['remind']
            type = reward['type']

            if type == "dailySignIn":
                award_notice = name
            if type == "dailyTask":
                task_notice = f'{remind}（{name}）'
        return success, '', award_notice, task_notice

def main() -> None:
    try:
        with open("./config.yaml", "r", encoding="utf-8") as file:
            config_data = yaml.safe_load(file)["Alidrive"]
    except Exception as e:
        logging.critical(f"阿里云盘配置读取失败{str(e)}")
        return
    else:
        if config_data["enable"]:
            ali = Aliyundrive()
            content = []
            for index, token in enumerate(config_data["refreshToken_List"]):
                logger.info(f"开始签到第{index + 1}个账户")
                result = ali.aliyundrive_check_in(token)
                content.append(str(result))

                if index +1 < len(config_data["refreshToken_List"]):
                    content.append('-----')

            logger.info("所有账户签到结束")
            #print(re.sub('\n+', '\n', '\n'.join(content)).rstrip('\n'))
            notify.send("阿里云盘已签到",re.sub('\n+', '\n', '\n'.join(content)).rstrip('\n'))
        else:
            logging.info("阿里云盘签到已关闭")
        return

if __name__ == "__main__":
    main()