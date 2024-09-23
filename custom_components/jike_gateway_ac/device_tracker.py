import json
import logging
import re
from os import path
import requests
import voluptuous as vol
import yaml
import hashlib  # 使用 hashlib 替代 js2py

import homeassistant.helpers.config_validation as cv
from homeassistant.exceptions import HomeAssistantError
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA)
from homeassistant.components.device_tracker.legacy import DeviceScanner
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_INCLUDE, CONF_LATITUDE, CONF_LONGITUDE

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_USERNAME): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Optional(CONF_INCLUDE, default=[]): vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_LATITUDE): vol.Coerce(float),
    vol.Optional(CONF_LONGITUDE): vol.Coerce(float),
})

class InvalidLuciTokenError(HomeAssistantError):
    """When an invalid token is detected."""
    pass

def get_scanner(hass, config):
    """Validate the configuration and return a Luci scanner."""
    scanner = Jike_Ac_GatewayDeviceScanner(config[DOMAIN])
    return scanner

class Jike_Ac_GatewayDeviceScanner(DeviceScanner):
    """This class queries a wireless router running OpenWrt firmware."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self._include = config[CONF_INCLUDE]
        if 'latitude' in config.keys() and 'longitude' in config.keys():
            self.latitude = config[CONF_LATITUDE]
            self.longitude = config[CONF_LONGITUDE]
            self.x_y_flag = 1
        else:
            self.x_y_flag = 0
        print(self.host, self.username, self.password)

        self.last_results = {}
        self.refresh_token()

        self.mac2name = None
        self.success_init = self.token is not None

    def refresh_token(self):
        """Get a new token."""
        self.token = _get_token(self.host, self.username, self.password)
        print(self.token)

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return self.last_results

    def get_extra_attributes(self, device):
        try:
            if self.result:
                if device in self.result:
                    if self.x_y_flag:
                        return {'rss': self.result[device]['rss'],
                                'AP': self.result[device]['ap'],
                                'ssid': self.result[device]['ssid'],
                                'latitude': self.latitude,
                                'longitude': self.longitude}
                    else:
                        return {'rss': self.result[device]['rss'],
                                'ssid': self.result[device]['ssid'],
                                'AP': self.result[device]['ap']}
                else:
                    return {}
            else:
                _LOGGER.error('out')
                return {}
        except Exception as e:
            _LOGGER.error(e)
        else:
            return {}

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        if self.result:
            if device in self.result.keys():
                return self.result[device]['hostname']
            else:
                return False
        else:
            return False

    def _update_info(self):
        """Ensure the information from the Luci router is up to date.

        Returns boolean if scanning successful.
        """
        self.last_results = []
        if not self.success_init:
            return False

        _LOGGER.info("集客网关AC 开始获取无线客户端数据")

        url = 'http://{}/api/apmgr'.format(self.host)
        header = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64)'
        }
        if self._include:
            search_key = str('|'.join(self._include))
        else:
            search_key = ""
        data = {
            "action": "stasearch",
            "pagenum": 1,
            "numperpage": 1000,
            "searchkey": search_key,
            "sortkey": "tx_rate",
            "reverse": "yes"
        }

        try:
            r_json = self.token.post(url, data=data, headers=header).json()
            _LOGGER.debug('apmgr_ret_json' + str(r_json))
            if "search" not in r_json["msg"]:
                self.refresh_token()
                _LOGGER.error("_update_info，cooking过期，需要重新登陆")
                return
            else:
                self.result = findallinfo(r_json)
        except InvalidLuciTokenError:
            _LOGGER.info("Refreshing token")
            self.refresh_token()
            return

        if self.result:
            self.last_results = [i for i in self.result]
            return True
        else:
            return

def _get_token(host, username, password):
    """Get authentication token for the given host+username+password."""
    url = 'http://{}/api/login'.format(host)
    return _req_json_rpc(url, 'login', username, password)

def _req_json_rpc(url, method, *args, **kwargs):
    """Perform one JSON RPC operation."""
    s = requests.Session()
    header = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64)'
    }
    ret_msg_json = s.get(url, headers=header).json()
    _LOGGER.debug('login_token:' + ret_msg_json["msg"])
    encrypt_password = _encryptpasswd(args[1], ret_msg_json["msg"])
    data = {
        "loginid": args[0],
        "passwd": encrypt_password
    }
    _LOGGER.debug(data)
    try:
        res = s.post(url, data=data, headers=header)
    except requests.exceptions.Timeout:
        _LOGGER.exception("Connection to the router timed out")
        return

    if res.status_code == 200:
        res_json = res.json()
        _LOGGER.debug(res_json)
        if '\u6210\u529f' not in res_json["msg"]:
            _LOGGER.exception("Failed to authenticate, check your username and password")
            return
        else:
            return s
    elif res.status_code == 401:
        _LOGGER.exception("Failed to authenticate, check your username and password")
        return
    elif res.status_code == 403:
        _LOGGER.exception("Luci responded with a 403 Invalid token")
        raise InvalidLuciTokenError
    else:
        _LOGGER.exception('Invalid response from luci: %s', res)
        return

def _encryptpasswd(password, msg):
    """Encrypt password using MD5."""
    first_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
    combined = first_hash + msg
    final_hash = hashlib.md5(combined.encode('utf-8')).hexdigest()
    _LOGGER.debug(final_hash)
    return final_hash

def findallinfo(ret_json):
    rest = {}
    for i in ret_json['stalist']:
        mac_f = ':'.join(format(s, '02x') for s in bytes.fromhex(i['mac'].upper()))
        rest[mac_f] = {
            "hostname": i["hostname"],
            "ip": i["ip"],
            "ap": i["name"],
            "ssid": i["ssid"],
            "rss": i["signal"]
        }
    return rest

