"""
A component which allows you to parse Mi Cloud get Mi Phone location info

For more details about this component, please refer to the documentation at
https://github.com/zrincet/MiPhone_tracker/

"""


import homeassistant.util.dt as dt_util
from homeassistant.helpers.entity import Entity
import requests
import json
import time
import hashlib
import base64
from urllib import parse
import logging
import re
from datetime import datetime, timedelta
import async_timeout
import asyncio
import aiohttp

import voluptuous as vol

from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_interval

from homeassistant.components.weather import ( PLATFORM_SCHEMA)
import homeassistant.helpers.config_validation as cv


__version__ = '0.1.0'
_LOGGER = logging.getLogger(__name__)
REQUIREMENTS = ['requests']
TIME_BETWEEN_UPDATES = timedelta(seconds=300)

CONF_OPTIONS = "options"
CONF_ACCOUNT = "account"
CONF_PASSWORD = "password"
CONF_CHOOSE = "device_choose"
CONF_DELTA = "update_delta"


PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_ACCOUNT): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_CHOOSE, default=1): cv.string,
    vol.Required(CONF_DELTA, default=300): cv.string,
})


@asyncio.coroutine
def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    _LOGGER.info("setup platform MiPhone tracker...")

    user = config[CONF_ACCOUNT]
    password = config[CONF_PASSWORD]
    choose = config[CONF_CHOOSE]

    data = MiPhoneData(hass, user, password, choose)

    yield from data.async_update(dt_util.now())
    global TIME_BETWEEN_UPDATES
    TIME_BETWEEN_UPDATES = timedelta(seconds=int(config[CONF_DELTA]))
    async_track_time_interval(hass, data.async_update, TIME_BETWEEN_UPDATES)
    async_add_devices([MiPhoneTracker(data)], True)


class MiPhoneTracker(Entity):

    def __init__(self, data):
        """Initialize."""
        self._name = None
        self._condition = None
        self._temperature = None
        self._temperature_unit = None
        self._humidity = None
        self._pressure = None
        self._wind_speed = None
        self._wind_bearing = None
        self._forecast = None

        self._data = data
        self._updatetime = None
        self._aqi = None
        self._uv = None

        self.device_name = None
        self.device_imei = None
        self.device_phone = None
        self.device_lat = None
        self.device_lon = None
        self.device_accuracy = None
        self.device_power = None
        self.device_location_update_time = None

    @property
    def name(self):
        return "Mi Cloud-" + self.device_name

    @property
    def state(self):
        return self.device_lat + ', ' + self.device_lon

    @property
    def icon(self):
        return "mdi:cellphone-android"

    @property
    def unique_id(self):
        return self.device_name

    @property
    def device_state_attributes(self):
        return {
            "update_time": self.device_location_update_time,
            "source_type": "gps",
            "battery_level": self.device_power,
            "latitude": self.device_lat,
            "longitude": self.device_lon,
            "gps_accuracy": self.device_accuracy,
            "altitude": 0,
            "provider": "Mi Cloud"
        }

    @asyncio.coroutine
    def async_update(self):
        """update函数变成了async_update."""
        self.device_name = self._data.device_name
        self.device_imei = self._data.device_imei
        self.device_phone = self._data.device_phone
        self.device_lat = self._data.device_lat
        self.device_lon = self._data.device_lon
        self.device_accuracy = self._data.device_accuracy
        self.device_power = self._data.device_power
        self.device_location_update_time = self._data.device_location_update_time
        # _LOGGER.debug("success to update informations")



class MiPhoneData(object):
    """获取相关的数据，存储在这个类中."""

    def __init__(self, hass, user=None, password=None, deviceChoose=None):
        """初始化函数."""
        self._hass = hass
        self.device_name = None
        self.device_imei = None
        self.device_phone = None
        self.device_lat = None
        self.device_lon = None
        self.device_accuracy = None
        self.device_power = None
        self.device_location_update_time = None
        self.deviceChoose = int(deviceChoose)

        self.login_result = False

        self._user = user
        self._password = password
        self.Service_Token = None
        self.userId = None
        self._cookies = {}
        self._requests = requests.session()
        self._headers = {'Host': 'account.xiaomi.com',
                         'Connection': 'keep-alive',
                         'Upgrade-Insecure-Requests': '1',
                         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
                         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                         'Accept-Encoding': 'gzip, deflate, br',
                         'Accept-Language': 'zh-CN,zh;q=0.9'}

    @property
    def name(self):
        """设备名称."""
        return self.device_name

    @property
    def source_type(self):
        return "gps"

    @property
    def battery_level(self):
        return self.device_power

    @property
    def latitude(self):
        return self.device_lat

    @property
    def longitude(self):
        return self.device_lon

    @property
    def gps_accuracy(self):
        return self.device_accuracy

    @property
    def altitude(self):
        return 0

    @property
    def provider(self):
        return "Mi Cloud"

    @property
    def updatetime(self):
        """更新时间."""
        return self.device_location_update_time

    async def _get_sign(self, session):
        url = 'https://account.xiaomi.com/pass/serviceLogin?sid%3Di.mi.com&sid=i.mi.com&_locale=zh_CN&_snsNone=true'
        pattern = re.compile(r'_sign":"(.*?)",')
        try:
            with async_timeout.timeout(15, loop=self._hass.loop):
                r = await session.get(url, headers=self._headers)
            self._cookies['pass_trace'] = r.headers.getall('Set-Cookie')[2].split("=")[1].split(";")[0]
            self._sign = pattern.findall(await r.text())[0]
            return True
        except BaseException as e:
            _LOGGER.warning(e.args[0])
            return False

    async def _serviceLoginAuth2(self, session, captCode=None):
        url = 'https://account.xiaomi.com/pass/serviceLoginAuth2'
        self._headers['Content-Type'] = 'application/x-www-form-urlencoded'
        self._headers['Accept'] = '*/*'
        self._headers['Origin'] = 'https://account.xiaomi.com'
        self._headers[
            'Referer'] = 'https://account.xiaomi.com/pass/serviceLogin?sid%3Di.mi.com&sid=i.mi.com&_locale=zh_CN&_snsNone=true'
        self._headers['Cookie'] = 'pass_trace={};'.format(
            self._cookies['pass_trace'])

        auth_post_data = {'_json': 'true',
                          '_sign': self._sign,
                          'callback': 'https://i.mi.com/sts',
                          'hash': hashlib.md5(self._password.encode('utf-8')).hexdigest().upper(),
                          'qs': '%3Fsid%253Di.mi.com%26sid%3Di.mi.com%26_locale%3Dzh_CN%26_snsNone%3Dtrue',
                          'serviceParam': '{"checkSafePhone":false}',
                          'sid': 'i.mi.com',
                          'user': self._user}
        try:
            if captCode != None:
                url = 'https://account.xiaomi.com/pass/serviceLoginAuth2?_dc={}'.format(
                    int(round(time.time() * 1000)))
                auth_post_data['captCode'] = captCode
                self._headers['Cookie'] = self._headers['Cookie'] + \
                                          '; ick={}'.format(self._cookies['ick'])
            with async_timeout.timeout(15, loop=self._hass.loop):
                r = await session.post(url, headers=self._headers, data=auth_post_data, cookies=self._cookies)
            self._cookies['pwdToken'] = r.cookies.get('passToken').value
            self._serviceLoginAuth2_json = json.loads((await r.text())[11:])
            return True
        except BaseException as e:
            _LOGGER.warning(e.args[0])
            return False

    async def _login_miai(self, session):
        serviceToken = "nonce={}&{}".format(
            self._serviceLoginAuth2_json['nonce'], self._serviceLoginAuth2_json['ssecurity'])
        serviceToken_sha1 = hashlib.sha1(serviceToken.encode('utf-8')).digest()
        base64_serviceToken = base64.b64encode(serviceToken_sha1)
        loginmiai_header = {'User-Agent': 'MISoundBox/1.4.0,iosPassportSDK/iOS-3.2.7 iOS/11.2.5',
                            'Accept-Language': 'zh-cn', 'Connection': 'keep-alive'}
        url = self._serviceLoginAuth2_json['location'] + \
              "&clientSign=" + parse.quote(base64_serviceToken.decode())
        try:
            with async_timeout.timeout(15, loop=self._hass.loop):
                r = await session.get(url, headers=loginmiai_header)
            if r.status == 200:
                self._Service_Token = r.cookies.get('serviceToken').value
                self.userId = r.cookies.get('userId').value
                return True
            else:
                return False
        except BaseException as e:
            _LOGGER.warning(e.args[0])
            return False

    async def _get_device_info(self, session):
        url = 'https://i.mi.com/find/device/full/status?ts={}'.format(
            int(round(time.time() * 1000)))
        get_device_list_header = {'Cookie': 'userId={};serviceToken={}'.format(
            self.userId, self._Service_Token)}
        try:
            with async_timeout.timeout(15, loop=self._hass.loop):
                r = await session.get(url, headers=get_device_list_header)
            if r.status == 200:
                self.device_name = json.loads(await
                    r.text())['data']['devices'][self.deviceChoose - 1]['model']
                self.device_imei = json.loads(await
                    r.text())['data']['devices'][self.deviceChoose - 1]['imei']
                self.device_phone = json.loads(await
                    r.text())['data']['devices'][self.deviceChoose - 1]['phone']

                return True
            else:
                return False
        except BaseException as e:
            _LOGGER.warning(e.args[0])
            return False

    async def _send_find_device_command(self, session):
        url = 'https://i.mi.com/find/device/{}/location'.format(
            self.device_imei)
        _send_find_device_command_header = {
            'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}
        data = {'userId': self.userId, 'imei': self.device_imei,
                'auto': 'false', 'channel': 'web', 'serviceToken': self._Service_Token}
        try:
            with async_timeout.timeout(15, loop=self._hass.loop):
                r = await session.post(url, headers=_send_find_device_command_header, data=data)
            if r.status == 200:
                return True
            else:
                self.login_result = False
                return False
        except BaseException as e:
            _LOGGER.warning(e.args[0])
            self.login_result = False
            return False

    async def _get_device_location(self, session):
        url = 'https://i.mi.com/find/device/status?ts={}&fid={}'.format(
            int(round(time.time() * 1000)), self.device_imei)
        _send_find_device_command_header = {
            'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}
        try:
            with async_timeout.timeout(15, loop=self._hass.loop):
                r = await session.get(url, headers=_send_find_device_command_header)
            if r.status == 200:
                self.device_lat = json.loads(
                    await r.text())['data']['location']['receipt']['gpsInfo']['latitude']
                self.device_accuracy = int(json.loads(
                    await r.text())['data']['location']['receipt']['gpsInfo']['accuracy'])
                self.device_lon = json.loads(
                    await r.text())['data']['location']['receipt']['gpsInfo']['longitude']
                self.device_power = json.loads(
                    await r.text())['data']['location']['receipt']['powerLevel']
                self.device_phone = json.loads(
                    await r.text())['data']['location']['receipt']['phone']
                timeArray = time.localtime(int(json.loads(
                    await r.text())['data']['location']['receipt']['infoTime']) / 1000 + 28800)
                self.device_location_update_time = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)

                return True
            else:
                self.login_result = False
                return False
        except BaseException as e:
            self.login_result = False
            _LOGGER.warning(e.args[0])
            return False

    @asyncio.coroutine
    def async_update(self, now):
        """从远程更新信息."""

        """
        # 异步模式的测试代码
        import time
        _LOGGER.info("before time.sleep")
        time.sleep(40)
        _LOGGER.info("after time.sleep and before asyncio.sleep")
        asyncio.sleep(40)
        _LOGGER.info("after asyncio.sleep and before yield from asyncio.sleep")
        yield from asyncio.sleep(40)
        _LOGGER.info("after yield from asyncio.sleep")
        """

        # 通过HTTP访问，获取需要的信息
        # 此处使用了基于aiohttp库的async_get_clientsession
        try:
            session = async_get_clientsession(self._hass)
            if self.login_result is True:
                tmp = yield from self._send_find_device_command(session)
                if tmp is True:
                    # time.sleep(15)
                    yield from asyncio.sleep(15)
                    tmp = yield from self._get_device_location(session)
                    if tmp is True:
                        _LOGGER.info("成功获取位置")
                        return
                    else:
                        _LOGGER.warning('get_device_location info Failed')

            session.cookie_jar.clear()
            tmp = yield from self._get_sign(session)
            if not tmp:
                _LOGGER.warning("get_sign Failed")
            else:
                tmp = yield from self._serviceLoginAuth2(session)
                if not tmp:
                    _LOGGER.warning('Request Login_url Failed')
                else:
                    if self._serviceLoginAuth2_json['code'] == 0:
                        # logon success,run self._login_miai()
                        tmp = yield from self._login_miai(session)
                        if not tmp:
                            _LOGGER.warning('login Mi Cloud Failed')
                        else:
                            tmp = yield from self._get_device_info(session)
                            if not tmp:
                                _LOGGER.warning('get_device info Failed')
                            else:
                                _LOGGER.info("get_device info succeed")
                                self.login_result = True
                                tmp = yield from self._send_find_device_command(session)
                                if tmp is True:
                                    #time.sleep(15)
                                    yield from asyncio.sleep(15)
                                    tmp = yield from self._get_device_location(session)
                                    if tmp is True:
                                        _LOGGER.info("get_device_location info succeed")
                                    else:
                                        _LOGGER.warning('get_device_location info Failed')

        except(asyncio.TimeoutError, aiohttp.ClientError):
            _LOGGER.error("Error while accessing: something wrong")
            return

        _LOGGER.info("success to fetch local info from Mi API")
