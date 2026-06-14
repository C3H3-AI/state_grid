"""
国家电网数据客户端 - v0.5.4

基于 bilezhou/state_grid 原版修改，主要变更:
1. 支持点选验证码（LLM 视觉大模型识别）
2. 支持滑块验证码（LLM + 像素算法双模式）
3. 自动检测验证码类型
4. 增加 LLM 配置（API Key, Base URL, Model）
5. 优化错误处理和重试逻辑
6. v0.5.0: RK001冷却机制（密码登录日额度用完后不再无效重试）
7. v0.5.1: 修复邮箱降级未被调用的问题 — RK001是账号维度的限流，
   手机号限流后邮箱仍可登录，遇到RK001时自动降级到邮箱登录
8. v0.5.2: 移除短信验证码登录（自动化系统无法手动输入验证码）
"""

import hashlib
import io
import base64
import json
import time
import urllib.parse
import datetime

from .const import VERSION, FLOW_CONTROL_CODES
from .utils.logger import LOGGER
from .utils.store import async_save_to_store
from .utils.crypt import a, b, c, d, e

from PIL import Image
from homeassistant.helpers.aiohttp_client import async_get_clientsession

# 直接导入 click_captcha_solver（模块内部使用懒加载，不会在导入时创建 openai 客户端）
from . import click_captcha_solver as _captcha_solver

MAX_RETRIES = 3

# ─── 字段名常量（保持原版混淆变量映射，可读性增强） ───
_F_canvasSrc = 'canvasSrc'
_F_blockSrc = 'blockSrc'
_F_blockY = 'blockY'
_F_iconSrc = 'iconSrc'
_F_wordSrc = 'wordSrc'
_F_iconSrcs = 'iconSrcs'
_F_ticket = 'ticket'

# ─── API 常量 ───
appKey = '7e5b5e84ddad4994b0ebc68dedca4962'
appSecret = '2bc37a881e1541aaa6e6e174658d150b'
baseApi = 'https://www.95598.cn/api'
get_request_key_api = '/oauth2/outer/c02/f02'
get_request_authorize_api = '/oauth2/oauth/authorize'
get_web_token_api = '/oauth2/outer/getWebToken'
get_verify_code_api = '/osg-web0004/open/c44/f05'
verify_password_api = '/osg-web0004/open/c44/f06'
click_card_api = '/osg-web0004/open/c44/f07'
get_door_number_api = '/osg-open-uc0001/member/c9/f02'
get_door_balance_api = '/osg-open-bc0001/member/c05/f01'
get_door_bill_api = '/osg-open-bc0001/member/c01/f02'
get_door_ladder_api = '/osg-open-bc0001/member/c04/f03'
get_door_daily_bill_api = '/osg-web0004/member/c24/f01'


sessionIdControlApiList = [verify_password_api, get_verify_code_api, click_card_api]
keyCodeControlApiList = [
    verify_password_api, get_verify_code_api, get_request_authorize_api,
    get_web_token_api, get_door_number_api, get_door_balance_api,
    get_door_bill_api, get_door_ladder_api, get_door_daily_bill_api,
    click_card_api
]
authControlApiList = [
    get_door_number_api, get_door_balance_api, get_door_bill_api,
    get_door_ladder_api, get_door_daily_bill_api
]
tControlApiList = [
    get_door_number_api, get_door_balance_api, get_door_bill_api,
    get_door_ladder_api, get_door_daily_bill_api
]

# ─── 业务配置 ───
configuration = {
    'uscInfo': {'member': '0902', 'devciceIp': '', 'devciceId': '', 'tenant': 'state_grid'},
    'source': 'SGAPP', 'target': '32101', 'channelCode': '0902',
    'channelNo': '0902', 'toPublish': '1',
    'siteId': '2012000000033700', 'srvCode': '', 'serialNo': '',
    'funcCode': '', 'serviceCode': {
        'ALIPAY_01': '0101154', 'uploadPic': '0101296',
        'pauseSCode': '0101250', 'pauseTCode': '0101251',
        'listconsumers': '0101093', 'messageList': '0101343',
        'submit': '0101003', 'sbcMsg': '0101210',
        'powercut': '0104514', 'BkAuth01': 'f15',
        'BkAuth02': 'f18', 'BkAuth03': 'f02',
        'BkAuth04': 'f17', 'BkAuth05': 'f05',
        'BkAuth06': 'f16', 'BkAuth07': 'f01',
        'BkAuth08': 'f03',
    },
    'electricityArchives': {'servicecode': '0104505', 'source': '0902'},
    'subscriptionList': {
        'srvCode': 'APP_SGPMS_05_030', 'serialNo': '22',
        'channelCode': '0902', 'funcCode': '22', 'target': '-1',
    },
    'userInformation': {'serviceCode': '01008183', 'source': 'SGAPP'},
    'userInform': {'serviceCode': '0101183', 'source': 'SGAPP'},
    'elesum': {
        'channelCode': '0902', 'funcCode': 'ALIPAY_01',
        'promotCode': '1', 'promotType': '1', 'serviceCode': '0101143',
        'source': 'app',
    },
    'account': {'channelCode': '0902', 'funcCode': 'WEBA1007200'},
    'doorAccountManeger': {
        'source': '0902', 'target': '-1', 'channelCode': '09',
        'channelNo': '09', 'serviceCode': '01010049',
        'funcCode': 'WEBA40050000',
        'uscInfo': {'member': '0902', 'devciceIp': '', 'devciceId': '', 'tenant': 'state_grid'},
    },
    'doorAuth': {'source': 'SGAPP', 'serviceCode': 'f04'},
    'xinZ': {
        'serCat': '101', 'jM_busiTypeCode': '101',
        'fJ_busiTypeCode': '102', 'jM_custType': '03',
        'fJ_custType': '02', 'serviceType': '1',
        'subBusiTypeCode': '', 'funcCode': 'WEBA10070700',
        'ALIPAY_01': '0101154', 'source': 'SGAPP', 'querytypeCode': '1',
    },
    'onedo': {'serviceCode': '0101046', 'source': 'SGAPP', 'funcCode': 'WEBA10070700', 'queryType': '03'},
    'xinHuTongDian': {
        'serCat': '110', 'busiTypeCode': '211', 'subBusiTypeCode': '21102',
        'funcCode': 'WEBA10071200', 'channelCode': '0902', 'source': '09',
        'serviceCode': '0101183',
    },
    'company': {
        'serCat': '104', 'funcCode': 'WEBA10070700', 'serviceType': '02',
        'querytypeCode': '1', 'authFlag': '1', 'source': 'SGAPP', 'ALIPAY_01': '0101154',
    },
    'charge': {
        'channelCode': '09', 'funcCode': 'WEBA10071300', 'channelNo': '0901',
        'serCat': '102', 'jM_custType': '1', 'jM_busiTypeCode': '102',
    },
    'other': {
        'channelCode': '09', 'funcCode': 'WEBA10079700', 'serCat': '129',
        'busiTypeCode': '999', 'subBusiTypeCode': '21501',
        'serviceCode': 'BCP_000026', 'srvCode': '', 'serialNo': '',
    },
    'vatchange': {
        'submit': '0101003', 'busiTypeCode': '320', 'subBusiTypeCode': '',
        'serCat': '115', 'funcCode': 'WEBA10074000', 'authFlag': '1',
    },
    'bill': {'getday': '1', 'funcCode': 'ALIPAY_01', 'promotType': '1', 'serviceCode': 'BCP_000026'},
    'stepelect': {
        'channelCode': '0902', 'funcCode': 'ALIPAY_01', 'promotType': '1',
        'getday': '09', 'serviceCode': 'BCP_000026', 'source': 'app',
    },
    'getday': {
        'channelCode': '0902', 'getday': '11', 'funcCode': 'ALIPAY_01',
        'promotCode': '1', 'promotType': '1', 'serviceCode': 'BCP_000026', 'source': 'app',
    },
    'mouthOut': {
        'channelCode': '0902', 'getday': '11', 'funcCode': 'ALIPAY_01',
        'promotCode': '1', 'promotType': '1', 'serviceCode': 'BCP_000026', 'source': 'app',
    },
    'meter': {
        'serCat': '114', 'busiTypeCode': '304', 'funcCode': 'WEBA10071000',
        'subBusiTypeCode': '', 'serviceCode': '0101046', 'serialNo': '',
    },
    'complaint': {
        'busiTypeCode': '005', 'srvMode': '0902', 'anonymousFlag': '0',
        'replyMode': '1', 'retvisitFlag': '1',
    },
    'report': {'busiTypeCode': '006'},
    'tradewinds': {'busiTypeCode': '019'},
    'somesay': {'busiTypeCode': '091'},
    'faultrepair': {
        'funcCode': 'WEBA10070900', 'serviceCode': '0101183',
        'serCat': '111', 'busiTypeCode': '001', 'subBusiTypeCode': '21505',
    },
    'electronicInvoice': {'serCat': '105', 'busiTypeCode': '0'},
    'rename': {
        'serviceCode': '0101046', 'funcCode': 'WEBA10076100',
        'busiTypeCode': '210', 'serCat': '109', 'authFlag': '1',
        'gh_busiTypeCode': '211', 'gh_subusi': '21101', 'serialNo': '', 'srvCode': '',
    },
    'pause': {
        'subBusiTypeCode': '', 'serviceCode': '01010049', 'funcCode': 'WEBA10073600',
        'serCat': '107', 'busiTypeCode': '203', 'jr_busi': '201',
        'serialNo': '', 'srvCode': '',
    },
    'capacityRecovery': {
        'serviceCode': '01010049', 'source': 'SGAPP', 'srvCode': '', 'serialNo': '',
        'funcCode': 'WEBA10073700', 'busiTypeCode_stop': '204',
        'busiTypeCode_less': '202', 'busiTypeCode': '202',
        'subBusiTypeCode': '', 'serCat': '108', 'refresh_interval': '5', 'authFlag': '1',
    },
    'electricityPriceChange': {
        'serviceCode': '0101183', 'busiTypeCode': '215', 'subBusiTypeCode': '21502',
        'serCat': '113', 'authFlag': '1', 'refresh_interval': '15',
        'funcCode': 'WEBA10073900WEB', 'srvCode': '', 'serialNo': '',
    },
    'electricityPriceStrategyChange': {
        'serviceCode': '01008183', 'busiTypeCode': '215', 'subBusiTypeCode': '21506',
        'serCat': '160', 'funcCode': 'WEBV00000517WEB', 'srvCode': '', 'serialNo': '',
    },
    'eemandValueAdjustment': {
        'serviceCode': '0101183', 'srvCode': '', 'serialNo': '', 'serCat': '112',
        'funcCode': 'WEBA10073800', 'busiTypeCode': '215', 'subBusiTypeCode': '21504',
        'authFlag': '1', 'refresh_interval': '5', 'getMonthServiceCode': '0101046',
    },
    'businessProgress': {
        'serviceCode': '0101183', 'subBusiTypeCode': '1', 'funcCode': 'WEB01',
    },
    'increase': {
        'source': 'SGAPP', 'serialNo': '', 'srvCode': '',
        'serviceCode_smt': '01010049', 'serviceCode': '0101154', 'ALIPAY_01': '0101154',
        'funcCode': 'WEBA10070800', 'querytypeCode': '1', 'serCat': '106',
        'busiTypeCode': '111', 'subBusiTypeCode': '',
    },
    'fjincrea': {
        'serCat': '105', 'busiTypeCode': '110', 'subBusiTypeCode': '',
        'source': 'SGAPP', 'funcCode': 'WEBA10070800', 'serialNo': '', 'srvCode': '',
        'serviceCode_smt': '01010049', 'serviceCode': '0101154', 'ALIPAY_01': '0101154',
        'querytypeCode': '1',
    },
    'persIncrea': {
        'serCat': '105', 'busiTypeCode': '109', 'ALIPAY_01': '0101154',
        'subBusiTypeCode': '', 'source': 'SGAPP', 'funcCode': 'WEBA10070800',
        'querytypeCode': '1',
    },
    'fgdChange': {
        'serviceCode': '0101183', 'subBusiTypeCode': '1', 'channelCode': '09',
        'funcCode': 'WEBA10070900', 'busiTypeCode': '215', 'subBusiTypeCode': '21505',
        'serCat': '111', 'authFlag': '1',
    },
    'createOrder': {
        'channelCode': '0902', 'funcCode': 'ALIPAY_01', 'srvCode': 'BCP_000001',
        'chargeMode': '02', 'conType': '1', 'bizTypeId': 'BT_ELEC',
    },
    'largePopulation': {
        'busiTypeCode': '383', 'funcCode': 'WEBA10076800', 'subBusiTypeCode': '',
        'srvCode': '', 'promotType': '', 'promotCode': '', 'channelCode': '0901',
        'serCat': '383', 'serviceCode': '', 'serialNo': '',
    },
    'biaoJiCode': {'serviceCode': '0104507', 'source': '1704', 'channelCode': '1704'},
    'twoGuar': {'busiTypeCode': '402', 'subBusiTypeCode': '40201', 'funcCode': 'web_twoGuar'},
    'electTrend': {'serviceCode': 'BCP_000026', 'channelCode': '0902'},
    'emergency': {'serviceCode': 'BCP_000026', 'funcCode': 'A10000000', 'channelCode': '0902'},
    'infoPublic': {'serviceCode': '2545454', 'source': 'app'},
}


# ─── 工具函数 ───

def json_dumps(data):
    return json.dumps(data, separators=(',', ':'), ensure_ascii=False)


def normal_round(num, ndigits=0):
    if ndigits == 0:
        return int(num + 0.5)
    else:
        factor = 10 ** ndigits
        return int(num * factor + 0.5) / factor


def catchFloat(data, key):
    if key in data:
        try:
            return normal_round(float(data[key]), 2)
        except Exception:
            return 0
    else:
        return 0


def catchInt(data, key):
    if key in data:
        try:
            return normal_round(float(data[key]), 0)
        except Exception:
            return 0
    else:
        return 0


def get_month_date_range(date_str):
    year = int(date_str[:4])
    month = int(date_str[4:])
    start = datetime.date(year, month, 1)
    if month == 12:
        next_month = 1
        next_year = year + 1
    else:
        next_month = month + 1
        next_year = year
    end = datetime.date(next_year, next_month, 1) - datetime.timedelta(days=1)
    return year, start, end


def base64_image_to_bytes(base64_data):
    if base64_data.startswith('data:image'):
        idx = base64_data.find(',')
        if idx != -1:
            base64_data = base64_data[idx + 1:]
    return base64.b64decode(base64_data)


def is_dark(pixel, threshold=100, method='brightness'):
    if len(pixel) == 4:
        r, g, b_val, a = pixel
        if a < 128:
            return False
    else:
        r, g, b_val = pixel

    if method == 'brightness':
        val = max(r, g, b_val)
    elif method == 'average':
        val = (r + g + b_val) // 3
    elif method == 'max':
        val = max(r, g, b_val)
    elif method == 'perceived':
        val = int(0.299 * r + 0.587 * g + 0.114 * b_val)
    else:
        raise ValueError(f"未知方法: {method}")
    return val < threshold


def find_max_rectangle(matrix):
    if not matrix or not matrix[0]:
        return 0, 0, 0, 0
    rows, cols = len(matrix), len(matrix[0])
    heights = [0] * cols
    max_area = 0
    best_rect = (0, 0, 0, 0)

    for row in range(rows):
        for col in range(cols):
            if matrix[row][col] == 1:
                heights[col] += 1
            else:
                heights[col] = 0

        stack = []
        for col in range(cols + 1):
            cur_h = heights[col] if col < cols else -1
            while stack and cur_h < heights[stack[-1]]:
                h = heights[stack.pop()]
                w = col if not stack else col - stack[-1] - 1
                area = h * w
                if area > max_area:
                    max_area = area
                    top_row = row - h + 1
                    left_col = col - w
                    best_rect = (top_row, left_col, row, col - 1)
            stack.append(col)
    return best_rect


# ─── 数据客户端 ───

class StateGridDataClient:
    hass = None
    coordinator = None
    session = None
    dataVersion = None
    keyCode = None
    publicKey = None
    need_login = False
    phone = None
    codeKey = None
    serialNo = None
    qrCodeSerial = None
    userInfo = None
    accountInfo = None
    powerUserList = None
    doorAccountDict = {}
    cookie = []
    timestamp = int(time.time() * 1000)
    accessToken = None
    refreshToken = None
    token = None
    expirationDate = None
    refresh_interval = 8
    is_debug = False
    shown_notification = False

    # LLM 配置
    llm_api_key = ""
    llm_base_url = "https://ark.cn-beijing.volces.com/api/v3"
    llm_model = "doubao-seed-2-0-pro-260215"

    # 备用邮箱（非RK001场景降级用）
    email_account = ""

    # RK001 冷却时间戳（手机号密码登录日额度用完后，避免无效重试）
    # 注意：RK001是账号维度的限流，邮箱账号不受手机号的RK001限制
    _rk001_cooldown_until = 0.0

    def __init__(self, hass, config=None):
        self.hass = hass
        if config is not None:
            try:
                self.keyCode = config.get('keyCode')
                self.publicKey = config.get('publicKey')
                self.accessToken = config.get('accessToken')
                self.refreshToken = config.get('refreshToken')
                self.token = config.get('token')
                self.userInfo = config.get('userInfo')
                self.powerUserList = config.get('powerUserList')
                self.doorAccountDict = config.get('doorAccountDict', {})
                self.is_debug = config.get('is_debug', False)
                self.dataVersion = config.get('dataVersion')
                self.account = config.get('account')
                self.password = config.get('password')
                self.refresh_interval = config.get('refresh_interval', 8)
                if self.refresh_interval < 8:
                    self.refresh_interval = 8
                # LLM 配置
                self.llm_api_key = config.get('llm_api_key', '')
                self.llm_base_url = config.get('llm_base_url', 'https://ark.cn-beijing.volces.com/api/v3')
                self.llm_model = config.get('llm_model', 'doubao-seed-2-0-pro-260215')
                # 备用邮箱
                self.email_account = config.get('email_account', '')
                # RK001 冷却
                self._rk001_cooldown_until = config.get('_rk001_cooldown_until', 0.0)
            except Exception as ex:
                LOGGER.error(f"初始化配置失败: {ex}")

        # 配置 LLM 客户端（延迟加载）
        if self.llm_api_key:
            _captcha_solver.configure_llm(
                self.llm_api_key,
                self.llm_base_url,
                self.llm_model,
            )

    async def save_data(self):
        data = {}
        data['keyCode'] = self.keyCode
        data['publicKey'] = self.publicKey
        data['accessToken'] = self.accessToken
        data['refreshToken'] = self.refreshToken
        data['token'] = self.token
        data['userInfo'] = self.userInfo
        data['powerUserList'] = self.powerUserList
        data['doorAccountDict'] = self.doorAccountDict
        data['is_debug'] = self.is_debug
        data['dataVersion'] = VERSION
        data['account'] = self.account
        data['password'] = self.password
        data['refresh_interval'] = self.refresh_interval
        # 保存 LLM 配置
        data['llm_api_key'] = self.llm_api_key
        data['llm_base_url'] = self.llm_base_url
        data['llm_model'] = self.llm_model
        # 保存备用邮箱
        data['email_account'] = self.email_account
        # 保存 RK001 冷却时间
        data['_rk001_cooldown_until'] = self._rk001_cooldown_until
        await async_save_to_store(self.hass, 'state_grid.config', data)

    def encrypt_post_data(self, data):
        wrapped = {
            '_access_token': self.accessToken[len(self.accessToken) // 2:] if self.accessToken else '',
            '_t': self.token[len(self.token) // 2:] if self.token else '',
            '_data': data,
            'timestamp': self.timestamp,
        }
        return self.encrypt_wapper_data(wrapped)

    def encrypt_wapper_data(self, data):
        encrypted = a(json_dumps(data), self.keyCode)
        return {
            'data': encrypted + c(encrypted + str(self.timestamp)),
            'skey': d(self.keyCode, self.publicKey),
            'timestamp': str(self.timestamp),
        }

    def handle_request_result_message(self, api, result, printResult=True):
        if self.is_debug and printResult:
            LOGGER.warning(api + '-' + json_dumps(result))
        msg = None
        if 'data' in result and result['data'] and 'srvrt' in result['data'] and 'resultMessage' in result['data']['srvrt']:
            msg = result['data']['srvrt']['resultMessage']
        elif 'srvrt' in result and 'resultMessage' in result['srvrt']:
            msg = result['srvrt']['resultMessage']
        elif 'message' in result:
            msg = result['message']
        else:
            msg = json_dumps(result)
        return msg

    # ─── 网络请求 ───

    async def __fetch_safe(self, api, data):
        result = await self.__fetch(api, data)
        if 'code' not in result:
            return result
        code = result['code']

        # 流控错误 (RK001): 当前账号密码登录日额度用完
        # RK001 是账号维度的限流，手机号限流后邮箱仍可登录
        if code in FLOW_CONTROL_CODES or self._is_flow_control_error(result):
            LOGGER.warning("[RK001] 数据API遇流控(code=%s), email_account=%s, cooldown=%s",
                           code, self.email_account or '(未配置)', self.is_rk001_cooldown())
            # 先尝试邮箱降级登录
            if self.email_account and not self.is_rk001_cooldown():
                LOGGER.info("[RK001] 当前账号被限流，尝试邮箱降级登录...")
                login_result = await self.__try_email_fallback_login()
                if login_result:
                    # 邮箱登录成功，重新请求数据
                    return await self.__fetch(api, data)
            elif not self.email_account:
                LOGGER.warning("[RK001] 未配置备用邮箱(email_account为空)，无法降级登录！请在HA集成配置中填写备用邮箱")
            # 邮箱降级也失败，设置冷却
            self._set_rk001_cooldown()
            self.need_login = True
            self._show_token_notification(
                msg='密码登录日额度已用完(RK001)，邮箱降级也失败，请等待明日0点自动重试'
            )
            return result

        # 其他需要重新登录的错误码
        if self.__need_login(code):
            await self.__try_password_login()
            if self.need_login is False:
                return await self.__fetch(api, data)
            if self.need_login is True:
                self._show_token_notification()
            return result
        else:
            return result

    def __need_login(self, code):
        # 11401=RK001限流（不触发常规重新登录，应由流控降级处理）
        # 10015=token失效, 10108/10009/10207=验证码相关
        # 10005/10010=账号异常, 30010/10002=其他需重新登录
        if code in (11401,):
            # 流控错误不触发重新登录，由调用方自行降级
            return False
        if code in (10015, 10108, 10009, 10207, 10005, 10010, 30010, 10002):
            self.need_login = True
            return True
        return False

    async def __try_password_login(self):
        LOGGER.debug("[登录流程] 开始, email_account=%s, rk001_cooldown=%s",
                     self.email_account or '(未配置)', self.is_rk001_cooldown())

        # 如果在 RK001 冷却期内，跳过手机号密码登录尝试
        if self.is_rk001_cooldown():
            # 冷却期内仍可尝试邮箱降级
            if self.email_account:
                LOGGER.info("[RK001冷却] 手机号在冷却期，尝试邮箱降级登录...")
                login_result = await self.__try_email_fallback_login()
                if login_result:
                    return
            else:
                LOGGER.warning("[RK001冷却] 跳过密码登录尝试，未配置邮箱降级，请等待明日0点")
            return

        # 先用当前账号（手机号）尝试登录
        result = await self.password_login(self.account, self.password, True, 3)
        LOGGER.debug("[登录流程] password_login 返回: errcode=%s, rk001=%s, errmsg=%s",
                     result.get('errcode'), result.get('rk001'), result.get('errmsg', '')[:60])

        if 'errcode' in result and result['errcode'] == 0:
            self.need_login = False
            self.shown_notification = False
            try:
                await self.save_data()
            except Exception as save_ex:
                LOGGER.exception("手机号登录成功但保存数据失败: %s", save_ex)
            return

        # 如果手机号命中RK001，尝试邮箱降级
        if self._is_flow_control_error(result):
            LOGGER.warning("[RK001] 手机号被限流，尝试邮箱降级登录 (email=%s)...", self.email_account or '(未配置)')
            login_result = await self.__try_email_fallback_login()
            if login_result:
                return
            # 邮箱降级也失败，设置冷却
            self._set_rk001_cooldown()
            return

    async def __fetch(self, api, data, header=None):
        self.timestamp = int(time.time() * 1000)
        ts = self.timestamp

        if self.keyCode is None:
            self.keyCode = e(32, 16, 2)

        key = self.keyCode
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept': 'application/json;charset=UTF-8',
            'Content-Type': 'application/json;charset=UTF-8',
            'version': '1.0',
            'source': '0901',
            'timestamp': str(ts),
            'wsgwType': 'web',
            'appKey': appKey,
            'Origin': 'https://www.95598.cn',
            'Referer': 'https://www.95598.cn/osgweb/login',
        }
        payload = data

        if api == get_request_key_api:
            payload = {'client_id': appKey, 'client_secret': appSecret}
            encrypted = a(json_dumps(payload), key)
            payload = {
                'data': encrypted + c(encrypted + str(ts)),
                'skey': d(key, '042D12DFBC179202AC4B7B7BADCDA6FF7B604339263F6AB732CE7107B7EA3830A2CA714DC303920D3CFF7647D898F1A8CC6C24E9EC3CC194E22D984AF7E16B42DC'),
                'client_id': appKey,
                'timestamp': str(ts),
            }
        elif api == get_request_authorize_api:
            if not self.token:
                LOGGER.error("authorize 调用但 self.token 为空，无法解密")
                return {'code': -1, 'message': 'authorize失败: token为空'}
            payload = {
                'client_id': appKey, 'response_type': 'code',
                'redirect_url': '/test', 'timestamp': ts, 'rsi': self.token,
            }
            payload = urllib.parse.urlencode(payload)
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers['keyCode'] = key
            session = async_get_clientsession(self.hass, False)
            async with session.post(baseApi + api, data=payload, headers=headers) as resp:
                text = await resp.text()
                if not text.startswith('{'):
                    LOGGER.warning(f"authorize API 返回非JSON响应 (HTTP {resp.status})，可能是流控")
                    return {'code': 11401, 'message': 'authorize返回非JSON响应，疑似IP限流'}
                try:
                    result = json.loads(text)
                    decrypted = b(result['data'], self.token)
                    result = json.loads(decrypted)
                    return result
                except Exception as ex:
                    LOGGER.exception("authorize 解密失败: %s, token=%s..., resp前200字符: %s", ex, self.token[:8] if self.token else 'None', text[:200])
                    return {'code': -1, 'message': f'authorize解密失败: {ex}'}
        elif api == get_web_token_api:
            payload = {
                'grant_type': 'authorization_code',
                'sign': c(appKey + str(ts)),
                'client_secret': appSecret,
                'state': '464606a4-184c-4beb-b442-2ab7761d0796',
                'key_code': key,
                'client_id': appKey,
                'timestamp': ts,
                'code': payload['code'],
            }
            encrypted = a(json_dumps(payload), key)
            payload = {
                'data': encrypted + c(encrypted + str(ts)),
                'skey': d(key, self.publicKey),
                'timestamp': str(ts),
            }
        else:
            payload = self.encrypt_post_data(payload)

        if header is not None:
            headers.update(header)
        if api in sessionIdControlApiList:
            headers['sessionId'] = 'web' + str(ts)
        if api in keyCodeControlApiList:
            headers['keyCode'] = key
        if api in authControlApiList:
            headers['Authorization'] = 'Bearer ' + self.accessToken[:len(self.accessToken) // 2]
        if api in tControlApiList:
            headers['t'] = self.token[:len(self.token) // 2]

        retry = 0
        while retry < MAX_RETRIES:
            try:
                session = async_get_clientsession(self.hass, False)
                async with session.post(baseApi + api, json=payload, headers=headers) as resp:
                    text = await resp.text()
                    if text.startswith('{'):
                        result = json.loads(text)
                        if 'encryptData' in result:
                            result = b(result['encryptData'], key)
                            result = json.loads(result)
                        return result
                    else:
                        # 非JSON返回（如 405 页面），视为流控/IP限流
                        LOGGER.warning(f"API {api} 返回非JSON响应 (HTTP {resp.status})，可能是流控")
                        return {'code': 11401, 'message': '服务端返回非JSON响应，疑似IP限流'}
            except Exception as ex:
                LOGGER.error(f"请求错误: {ex}. 尝试第 {retry + 1} 次重试...")
                retry += 1
                if retry == MAX_RETRIES:
                    raise ex

    # ─── 登录相关 ───

    async def __get_request_key(self):
        self.keyCode = None
        result = await self.__fetch(get_request_key_api, {})
        msg = self.handle_request_result_message('get_request_key_api', result)
        if str(result.get('code', '')) == '1':
            self.keyCode = result['data']['keyCode']
            self.publicKey = result['data']['publicKey']
            return {'errcode': 0}
        # 保留原始错误码，便于流控检测
        raw_code = result.get('code')
        return {'errcode': 1, 'errmsg': msg, 'raw_code': raw_code}

    async def __get_pass_verify_code(self, account, password):
        """获取验证码，支持滑块和点选两种类型。"""
        params = {
            'account': account,
            'password': password,
            'canvasHeight': 200,
            'canvasWidth': 310,
        }
        result = await self.__fetch(get_verify_code_api, params)
        msg = self.handle_request_result_message('get_verify_code_api', result, False)

        # 修复：API 返回的 code 可能是 int 1 或 str '1'，统一用 str 比较
        if 'code' in result and str(result['code']) == '1' and 'data' in result:
            data = result['data']
            self.ticket = data.get('ticket', '')

            # 检测验证码类型
            captcha_type = _captcha_solver.detect_captcha_type(data)
            LOGGER.info(f"检测到验证码类型: {captcha_type}")

            # 调试：打印 f05 返回的所有字段名
            LOGGER.debug(f"验证码API返回字段: {list(data.keys())}")

            return_data = {
                'errcode': 0,
                'captcha_type': captcha_type,
                'ticket': self.ticket,
            }

            # 复制所有验证码相关字段（不区分滑块/点选，全部传递）
            for key in data:
                if key in (_F_canvasSrc, _F_blockSrc, _F_blockY,
                           _F_iconSrc, _F_wordSrc, _F_iconSrcs):
                    return_data[key] = data[key]
                    LOGGER.debug(f"  验证码字段 {key}: {str(data[key])[:80]}...")

            return return_data

        LOGGER.error(f"获取验证码失败, code={result.get('code')}, msg={msg}")
        # 保留原始错误码，便于流控检测
        raw_code = result.get('code')
        return {'errcode': 1, 'errmsg': msg, 'raw_code': raw_code}

    async def __verify_password(self, account, password, code, loginKey, captcha_type='slider'):
        """验证密码登录。

        参数:
            code: 滑块模式为距离(int)，点选模式为坐标字符串(如 "x1,y1|x2,y2|x3,y3")
            captcha_type: 验证码类型 "slider" 或 "click"
        """
        params = {
            'loginKey': loginKey,
            'code': code,
            'params': {
                'uscInfo': {
                    'devciceIp': '', 'tenant': 'state_grid',
                    'member': '0902', 'devciceId': '',
                },
                'quInfo': {
                    'optSys': 'android', 'pushId': '000000',
                    'addressProvince': '110100', 'password': password,
                    'addressRegion': '110101', 'account': account,
                    'addressCity': '330100',
                },
            },
            'Channels': 'web',
        }

        # 根据验证码类型添加 complexSliderRet 和 complexSliderType 字段
        # 参考 Yuheng0101/X 实现：95598 API 需要这些字段来区分验证码类型
        if captcha_type == 'click':
            params['complexSliderRet'] = 0
            params['complexSliderType'] = 'clickImg'
        elif captcha_type == 'slider':
            params['complexSliderRet'] = 0
            params['complexSliderType'] = 'blockPuzzle'

        # 调试日志：打印提交的验证码参数
        LOGGER.info(f"提交验证码: type={captcha_type}, code_type={type(code).__name__}, code={code}, loginKey={loginKey[:20] if loginKey else 'None'}...")

        result = await self.__fetch(verify_password_api, params)
        msg = self.handle_request_result_message('verify_password_api', result)
        LOGGER.debug(f"验证密码结果: code={result.get('code')}, msg={msg}")

        # 修复：API 返回的 code 可能是 int 1 或 str '1'，统一用 str 比较
        if 'code' in result and str(result['code']) == '1':
            if result['data'] and result['data'].get('srvrt') and result['data']['srvrt'].get('resultCode') == '0000':
                self.token = result['data']['bizrt']['token']
                self.userInfo = result['data']['bizrt']['userInfo'][0]
                return {'errcode': 0}
        # 保留原始错误码，便于流控检测
        raw_code = result.get('code')
        return {'errcode': 1, 'errmsg': msg, 'raw_code': raw_code}

    async def __verify_click_captcha(self, account, password, code, loginKey):
        """使用 f07 (clickCard) 端点验证点选验证码。

        95598 API 有专门的 clickCard 端点用于点选验证码验证，
        如果 f07 失败则回退到 f06 + complexSliderType 方式。
        """
        params = {
            'loginKey': loginKey,
            'code': code,
            'params': {
                'uscInfo': {
                    'devciceIp': '', 'tenant': 'state_grid',
                    'member': '0902', 'devciceId': '',
                },
                'quInfo': {
                    'optSys': 'android', 'pushId': '000000',
                    'addressProvince': '110100', 'password': password,
                    'addressRegion': '110101', 'account': account,
                    'addressCity': '330100',
                },
            },
            'Channels': 'web',
        }

        LOGGER.info(f"提交点选验证码(f07/clickCard): code={code}, loginKey={loginKey[:20] if loginKey else 'None'}...")

        result = await self.__fetch(click_card_api, params)
        msg = self.handle_request_result_message('click_card_api', result)
        LOGGER.debug(f"clickCard 结果: code={result.get('code')}, msg={msg}")

        # 修复：API 返回的 code 可能是 int 1 或 str '1'，统一用 str 比较
        if 'code' in result and str(result['code']) == '1':
            if result['data'] and result['data'].get('srvrt') and result['data']['srvrt'].get('resultCode') == '0000':
                self.token = result['data']['bizrt']['token']
                self.userInfo = result['data']['bizrt']['userInfo'][0]
                return {'errcode': 0}

        LOGGER.warning(f"clickCard(f07) 验证失败: {msg}，尝试回退到 f06 + complexSliderType...")
        # 保留原始错误码，便于流控检测
        raw_code = result.get('code')
        return {'errcode': 1, 'errmsg': msg, 'raw_code': raw_code}

    async def __get_request_authorize(self):
        result = await self.__fetch(get_request_authorize_api, {})
        msg = self.handle_request_result_message('get_request_authorize_api', result)
        if 'code' in result and result['code'] == '1':
            redirect_url = result['data']['redirect_url']
            idx = redirect_url.rfind('code=')
            self.authorizeCode = redirect_url[idx + 5:idx + 5 + 32]
            return {'errcode': 0}
        return {'errcode': 1, 'errmsg': msg}

    async def __get_web_token(self):
        params = {'code': self.authorizeCode}
        result = await self.__fetch(get_web_token_api, params)
        msg = self.handle_request_result_message('get_web_token_api', result)
        if 'code' in result and result['code'] == '1':
            self.accessToken = result['data']['access_token']
            self.refreshToken = result['data']['refresh_token']
            return {'errcode': 0}
        return {'errcode': 1, 'errmsg': msg}

    # ─── 验证码解算 ───

    def _solve_slider_captcha_pixel(self, captcha_data: dict) -> int:
        """使用像素算法解算滑块验证码（原版逻辑，作为 LLM 的后备方案）。"""
        block_y = int(captcha_data.get(_F_blockY, 0))
        block_height = 0

        # 获取背景图
        block_bytes = base64_image_to_bytes(captcha_data.get(_F_blockSrc, ''))
        with Image.open(io.BytesIO(block_bytes)) as bg_img:
            bg_w, bg_h = bg_img.size
            block_height = bg_h

        # 获取 canvas 图并裁剪
        canvas_bytes = base64_image_to_bytes(captcha_data.get(_F_canvasSrc, ''))
        with Image.open(io.BytesIO(canvas_bytes)) as canvas_img:
            cw, ch = canvas_img.size
            cropped = canvas_img.crop((0, block_y, cw, block_y + block_height))
            # 二值化处理
            binary = cropped.point(lambda p: 255 if p > 150 else 0)

        # 构建二值矩阵
        w, h = binary.width, binary.height
        matrix = [[0 for _ in range(h)] for _ in range(w)]
        for y in range(h):
            for x in range(w):
                pixel = binary.getpixel((x, y))
                if is_dark(pixel, 100):
                    matrix[x][y] = 1
                else:
                    matrix[x][y] = 0

        # 找最大矩形获取滑块距离
        top, left, bottom, right = find_max_rectangle(matrix)
        distance = left
        LOGGER.info(f"像素算法滑块距离: {distance}")
        return distance

    def _solve_slider_captcha_llm(self, captcha_data: dict) -> int:
        """使用 LLM 解算滑块验证码。"""
        try:
            canvas_base64 = captcha_data.get(_F_canvasSrc, '')
            if not canvas_base64:
                return 0
            return _captcha_solver.solve_slider_captcha_llm(
                canvas_base64,
                canvas_width=310,
                canvas_height=200,
            )
        except NotImplementedError:
            # httpx/openai 内部异常，向上抛出让调用方处理重试
            raise
        except Exception as ex:
            LOGGER.exception("LLM 滑块解算失败: %s", ex)
            return 0

    def _solve_click_captcha(self, captcha_data: dict) -> str:
        """使用 LLM 解算点选验证码，返回坐标字符串。"""
        try:
            # 获取参考图标条
            ref_base64 = captcha_data.get(_F_iconSrc, '') or captcha_data.get(_F_wordSrc, '')
            if not ref_base64 and _F_iconSrcs in captcha_data:
                # 如果有多个图标，拼接为一条
                icons = captcha_data[_F_iconSrcs]
                if isinstance(icons, list) and len(icons) > 0:
                    # 取第一个作为参考（也可能是所有图标）
                    ref_base64 = icons[0] if isinstance(icons[0], str) else ''

            # 获取主图
            main_base64 = captcha_data.get(_F_canvasSrc, '')
            if not ref_base64 or not main_base64:
                LOGGER.error("点选验证码缺少参考图标或主图数据")
                return ""

            # 解析主图尺寸
            main_bytes = base64_image_to_bytes(main_base64)
            with Image.open(io.BytesIO(main_bytes)) as main_img:
                main_w, main_h = main_img.size

            coords = _captcha_solver.solve_click_captcha(
                ref_base64, main_base64, main_w, main_h
            )

            if not coords or len(coords) < 2:
                LOGGER.error("LLM 未能识别点选验证码坐标")
                return ""

            # 格式化为坐标字符串
            # 根据国网 API 的实际需求，可能需要调整为 "x1,y1|x2,y2|x3,y3"
            # 或者其他格式。这里先按常见格式输出
            coord_str = "|".join([f"{x},{y}" for x, y in coords])
            LOGGER.info(f"点选验证码坐标: {coord_str}")
            return coord_str

        except NotImplementedError:
            # httpx/openai 内部异常，向上抛出让调用方处理重试
            raise
        except Exception as ex:
            LOGGER.exception("点选验证码解算失败: %s", ex)
            return ""

    # ─── 主登录流程 ───

    @staticmethod
    def _is_flow_control_error(result):
        """判断 API 返回结果是否为流控（限流）错误。

        支持两种返回格式:
        - 原始 API 返回: {'code': 11401, 'message': '...'}
        - 内部方法返回: {'errcode': 1, 'errmsg': '...', 'raw_code': 11401}
        """
        # 检查原始 API 错误码 (code 字段)
        code = result.get('code')
        if code is not None:
            try:
                code_int = int(code)
                if code_int in FLOW_CONTROL_CODES:
                    return True
            except (ValueError, TypeError):
                pass

        # 检查内部方法保留的原始错误码 (raw_code 字段)
        raw_code = result.get('raw_code')
        if raw_code is not None:
            try:
                if int(raw_code) in FLOW_CONTROL_CODES:
                    return True
            except (ValueError, TypeError):
                pass

        # 检查错误消息中的限流关键词（包括 RK001）
        errmsg = (result.get('errmsg', '') or result.get('message', '') or '')
        flow_keywords = ('限流', '频繁', '限制', 'rk001', 'flow', 'rate', 'too many')
        errmsg_lower = errmsg.lower()
        if any(kw in errmsg_lower for kw in flow_keywords):
            return True

        # 检查 rk001 标记字段（password_login 内部返回的流控标记）
        if result.get('rk001'):
            return True

        # 检查 errcode 本身是否为流控码
        errcode = result.get('errcode')
        if errcode is not None:
            try:
                if int(errcode) in FLOW_CONTROL_CODES:
                    return True
            except (ValueError, TypeError):
                pass

        # 检查 srvrt 中的错误信息
        if 'data' in result and result['data'] and isinstance(result['data'], dict) and 'srvrt' in result['data']:
            srvrt_msg = result['data']['srvrt'].get('resultMessage', '')
            if any(kw in srvrt_msg.lower() for kw in flow_keywords):
                return True

        return False

    async def password_login(self, account, password, encode=False, retry=0):
        """账号密码登录。

        注意: RK001(11401)是账号维度的密码登录日额度限制。
        手机号被限流后，邮箱账号仍可正常登录（自动降级）。
        """
        # RK001 冷却期内，不再尝试手机号密码登录
        # （但不阻止邮箱降级登录，邮箱不受手机号的RK001限制）
        if self.is_rk001_cooldown() and account == self.account:
            LOGGER.warning("[RK001冷却] 跳过手机号密码登录，冷却至 %s",
                           time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._rk001_cooldown_until)))
            return {'errcode': 1, 'errmsg': '手机号密码登录日额度已用完(RK001)'}

        pwd = password
        if not encode:
            pwd = hashlib.md5(pwd.encode()).hexdigest().upper()

        # 步骤 1: 获取加密密钥
        result = await self.__get_request_key()
        if result.get('errcode') != 0:
            # 获取密钥阶段遇流控，直接返回让调用方处理降级
            if self._is_flow_control_error(result):
                return {'errcode': 1, 'errmsg': '获取密钥遇流控(RK001)，密码登录日额度已用完', 'rk001': True}
            return result

        # 步骤 2: 获取验证码
        result = await self.__get_pass_verify_code(account, pwd)
        if result.get('errcode') != 0:
            # 获取验证码阶段遇流控，直接返回让调用方处理降级
            if self._is_flow_control_error(result):
                return {'errcode': 1, 'errmsg': '获取验证码遇流控(RK001)，密码登录日额度已用完', 'rk001': True}
            return result

        # 步骤 3: 解算验证码
        captcha_type = result.get('captcha_type', 'slider')
        verify_code = None

        try:
            if captcha_type == 'click':
                # 点选验证码 - 使用 LLM 解算（在 executor 中运行避免阻塞事件循环）
                LOGGER.info("正在使用 LLM 解算点选验证码...")
                verify_code = await self.hass.async_add_executor_job(
                    self._solve_click_captcha, result
                )
                if not verify_code:
                    # LLM 解算失败，尝试刷新重试
                    if retry <= 0:
                        return {'errcode': 1, 'errmsg': '点选验证码解算失败'}
                    LOGGER.error('点选验证码解算失败，将重试！')
                    result = await self.password_login(account, pwd, True, retry - 1)
                    if result.get('errcode') != 0:
                        return result

            elif captcha_type == 'slider':
                # 滑块验证码 - 优先使用 LLM，失败回退像素算法
                if self.llm_api_key:
                    LOGGER.info("正在使用 LLM 解算滑块验证码...")
                    verify_code = await self.hass.async_add_executor_job(
                        self._solve_slider_captcha_llm, result
                    )
                    if verify_code == 0:
                        LOGGER.warning("LLM 滑块解算失败，回退到像素算法...")
                        verify_code = await self.hass.async_add_executor_job(
                            self._solve_slider_captcha_pixel, result
                        )
                else:
                    LOGGER.info("未配置 LLM，使用像素算法解算滑块验证码...")
                    verify_code = await self.hass.async_add_executor_job(
                        self._solve_slider_captcha_pixel, result
                    )

            else:
                LOGGER.warning(f"未知验证码类型: {captcha_type}，尝试按滑块处理")
                verify_code = await self.hass.async_add_executor_job(
                    self._solve_slider_captcha_pixel, result
                )
        except NotImplementedError:
            LOGGER.error("验证码解算遇到 NotImplementedError（httpx/openai 内部异常）")
            if retry <= 0:
                return {'errcode': 1, 'errmsg': '验证码解算内部错误(NotImplementedError)'}
            LOGGER.warning('验证码解算异常，重试...')
            return await self.password_login(account, pwd, True, retry - 1)

        # 步骤 4: 提交验证（点选和滑块使用不同的验证流程）
        if captcha_type == 'click':
            # 点选验证码：先尝试 f07 (clickCard) 端点，失败则回退到 f06 + complexSliderType
            result = await self.__verify_click_captcha(account, pwd, verify_code, self.ticket)
            if result.get('errcode') != 0:
                # f07 失败，回退到 f06 + complexSliderType=clickImg
                LOGGER.warning('f07 clickCard 失败，回退到 f06 + complexSliderType=clickImg...')
                result = await self.__verify_password(account, pwd, verify_code, self.ticket, captcha_type='click')
        else:
            # 滑块验证码：使用 f06 + complexSliderType=blockPuzzle
            result = await self.__verify_password(account, pwd, verify_code, self.ticket, captcha_type='slider')
        if result.get('errcode') != 0:
            # 验证阶段遇流控，直接返回让调用方处理降级
            if self._is_flow_control_error(result):
                return {'errcode': 1, 'errmsg': '验证登录遇流控(RK001)，密码登录日额度已用完', 'rk001': True}
            if retry <= 0:
                return result
            LOGGER.error('账号密码登录失败，将重试！')
            result = await self.password_login(account, pwd, True, retry - 1)
            if result.get('errcode') != 0:
                return result

        self.account = account
        self.password = pwd
        return await self.__get_token()

    async def __try_email_fallback_login(self):
        """尝试邮箱降级登录，成功返回True，失败返回False。"""
        if not self.email_account:
            LOGGER.warning("[邮箱降级] 未配置备用邮箱，无法降级")
            return False

        pwd = self.password
        if not pwd:
            LOGGER.warning("[邮箱降级] 密码为空，无法降级")
            return False

        try:
            result = await self._login_with_email_fallback(pwd, retry=2)
            if result.get('errcode') == 0:
                self.need_login = False
                self.shown_notification = False
                LOGGER.info("[邮箱降级] 登录成功! 使用邮箱 %s 替代手机号登录", self.email_account)
                try:
                    await self.save_data()
                except Exception as save_ex:
                    LOGGER.exception("邮箱登录成功但保存数据失败: %s", save_ex)
                return True
            else:
                errmsg = result.get('errmsg', '')
                LOGGER.warning("[邮箱降级] 登录失败: %s", errmsg)
                if self._is_flow_control_error(result):
                    LOGGER.warning("[邮箱降级] 邮箱账号也被限流(RK001)，设置冷却")
                    self._set_rk001_cooldown()
                return False
        except Exception as ex:
            LOGGER.exception("[邮箱降级] 登录异常: %s (type=%s)", ex, type(ex).__name__)
            return False

    async def _login_with_email_fallback(self, pwd, retry=0):
        """使用备用邮箱登录（流控降级）。

        RK001是账号维度的限流，手机号被限流后邮箱仍可正常登录。
        此方法在手机号遇到RK001时自动调用，无需用户干预。
        """
        if not self.email_account:
            return {'errcode': 1, 'errmsg': '未配置备用邮箱，无法降级登录'}
        LOGGER.info("=== 流控降级：使用邮箱 %s 登录 ===", self.email_account)
        try:
            # 步骤1: 获取密钥（邮箱登录使用新的密钥）
            result = await self.__get_request_key()
            if result.get('errcode') != 0:
                LOGGER.warning("[邮箱降级] 获取密钥失败: %s", result.get('errmsg', ''))
                if self._is_flow_control_error(result):
                    self._set_rk001_cooldown()
                    return {'errcode': 1, 'errmsg': '邮箱降级：获取密钥遇流控(RK001)'}
                return result

            # 步骤2: 获取验证码
            result = await self.__get_pass_verify_code(self.email_account, pwd)
            if result.get('errcode') != 0:
                LOGGER.warning("[邮箱降级] 获取验证码失败: %s", result.get('errmsg', ''))
                if self._is_flow_control_error(result):
                    self._set_rk001_cooldown()
                    return {'errcode': 1, 'errmsg': '邮箱降级：获取验证码遇流控(RK001)'}
                return result

            # 步骤3: 解算验证码（独立 try-except，捕获 httpx/openai 等库的内部异常）
            captcha_type = result.get('captcha_type', 'slider')
            verify_code = None

            try:
                if captcha_type == 'click':
                    LOGGER.info("[邮箱降级] 正在使用 LLM 解算点选验证码...")
                    verify_code = await self.hass.async_add_executor_job(
                        self._solve_click_captcha, result
                    )
                    if not verify_code:
                        if retry <= 0:
                            return {'errcode': 1, 'errmsg': '邮箱降级：点选验证码解算失败'}
                        LOGGER.warning('[邮箱降级] 点选验证码解算失败，重试...')
                        return await self._login_with_email_fallback(pwd, retry - 1)
                elif captcha_type == 'slider':
                    if self.llm_api_key:
                        LOGGER.info("[邮箱降级] 正在使用 LLM 解算滑块验证码...")
                        verify_code = await self.hass.async_add_executor_job(
                            self._solve_slider_captcha_llm, result
                        )
                        if verify_code == 0:
                            LOGGER.warning("[邮箱降级] LLM 滑块解算失败，回退像素算法...")
                            verify_code = await self.hass.async_add_executor_job(
                                self._solve_slider_captcha_pixel, result
                            )
                    else:
                        verify_code = await self.hass.async_add_executor_job(
                            self._solve_slider_captcha_pixel, result
                        )
                else:
                    verify_code = await self.hass.async_add_executor_job(
                        self._solve_slider_captcha_pixel, result
                    )
            except NotImplementedError as nie:
                LOGGER.error("[邮箱降级] 验证码解算遇到 NotImplementedError（httpx/openai 内部异常）: %s", nie)
                if retry <= 0:
                    return {'errcode': 1, 'errmsg': f'邮箱降级：验证码解算内部错误(NotImplementedError)'}
                LOGGER.warning('[邮箱降级] 验证码解算异常，重试...')
                return await self._login_with_email_fallback(pwd, retry - 1)
            except Exception as cap_ex:
                LOGGER.exception("[邮箱降级] 验证码解算异常: %s (type=%s)", cap_ex, type(cap_ex).__name__)
                if retry <= 0:
                    return {'errcode': 1, 'errmsg': f'邮箱降级：验证码解算异常({type(cap_ex).__name__})'}
                LOGGER.warning('[邮箱降级] 验证码解算异常，重试...')
                return await self._login_with_email_fallback(pwd, retry - 1)

            # 步骤4: 提交验证
            if captcha_type == 'click':
                result = await self.__verify_click_captcha(self.email_account, pwd, verify_code, self.ticket)
                if result.get('errcode') != 0:
                    result = await self.__verify_password(self.email_account, pwd, verify_code, self.ticket, captcha_type='click')
            else:
                result = await self.__verify_password(self.email_account, pwd, verify_code, self.ticket, captcha_type='slider')

            if result.get('errcode') != 0:
                LOGGER.warning("[邮箱降级] 验证失败: %s", result.get('errmsg', ''))
                if self._is_flow_control_error(result):
                    self._set_rk001_cooldown()
                    return {'errcode': 1, 'errmsg': '邮箱降级：验证登录遇流控(RK001)，邮箱也被限流'}
                if retry <= 0:
                    return result
                LOGGER.warning('[邮箱降级] 登录失败，重试...')
                return await self._login_with_email_fallback(pwd, retry - 1)

            # 步骤5: 获取 token
            # 注意：登录成功后 self.account 改为邮箱，但后续数据查询仍使用同一账号体系
            self.account = self.email_account
            self.password = pwd
            LOGGER.info("[邮箱降级] 邮箱登录验证通过，正在获取token...")
            return await self.__get_token()

        except Exception as ex:
            LOGGER.exception("[邮箱降级] 登录异常: %s (type=%s)", ex, type(ex).__name__)
            return {'errcode': 1, 'errmsg': f'邮箱降级登录异常: {ex}'}

    async def __get_token(self):
        result = await self.__get_request_authorize()
        if result.get('errcode') != 0:
            return result
        result = await self.__get_web_token()
        if result.get('errcode') != 0:
            return result
        self.need_login = False
        try:
            await self.save_data()
        except Exception as ex:
            LOGGER.exception("登录成功但保存数据失败: %s", ex)
            # 保存失败不影响登录成功
        return {'errcode': 0}

    def _show_token_notification(self, msg=None):
        if self.shown_notification:
            return
        self.shown_notification = True
        import persistent_notification
        if msg is None:
            msg = '国家电网登录失败，将在下个轮询重试'
        persistent_notification.create(self.hass, msg, title='国家电网 - 登录失败')
        LOGGER.error(msg)

    def is_rk001_cooldown(self):
        """检查当前是否处于 RK001 冷却期。

        RK001 = 密码登录日额度用完。冷却期间不应再尝试密码登录，
        避免浪费剩余额度或触发更严厉的限制。

        冷却策略: RK001命中后，设置冷却到当天 23:59:59（北京时间），
        即第二天0点后自动解除。
        """
        if self._rk001_cooldown_until <= 0:
            return False
        now = time.time()
        return now < self._rk001_cooldown_until

    def _set_rk001_cooldown(self):
        """设置 RK001 冷却到当天 23:59:59（北京时间）。"""
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=8)))
        end_of_day = now.replace(hour=23, minute=59, second=59, microsecond=0)
        self._rk001_cooldown_until = end_of_day.timestamp()
        LOGGER.warning(
            "[RK001冷却] 密码登录日额度已用完，冷却至 %s（北京时间），期间不再尝试密码登录",
            end_of_day.strftime('%Y-%m-%d %H:%M:%S'),
        )

    # ─── 数据获取 ───

    async def __get_door_number(self):
        cfg = configuration['doorAccountManeger']
        params = {
            'serviceCode': cfg['serviceCode'],
            'source': cfg['source'],
            'target': cfg['target'],
            'uscInfo': {
                'member': cfg['uscInfo']['member'],
                'devciceIp': cfg['uscInfo']['devciceIp'],
                'devciceId': cfg['uscInfo']['devciceId'],
                'tenant': cfg['uscInfo']['tenant'],
            },
            'quInfo': {'userId': self.userInfo['userId']},
            'token': self.token,
        }
        result = await self.__fetch_safe(get_door_number_api, params)
        msg = self.handle_request_result_message('get_door_number_api', result)
        if 'code' in result and str(result['code']) in ('1', '0000', '000000') and 'data' in result and 'bizrt' in result['data']:
            exist_map = {}
            if self.powerUserList is not None:
                exist_map = {item['consNo_dst']: item for item in self.powerUserList}
            new_list = []
            for item in result['data']['bizrt']['powerUserList']:
                if item['consNo_dst'] in exist_map:
                    new_list.append(exist_map[item['consNo_dst']])
                else:
                    # 过滤 elecTypeCode='05'（非居民用户），保留其他所有户表
                    # 注意：有些返回可能没有 elecTypeCode 字段，此时应保留
                    elec_type = item.get('elecTypeCode', '')
                    if elec_type != '05':
                        # 确保每项都有 consType 字段（余额查询必需）
                        if 'consType' not in item:
                            item['consType'] = '1'  # 默认预付费
                            LOGGER.warning("[户号] %s 缺少consType字段，默认设为'1'(预付费)", item.get('consNo_dst', '?'))
                        new_list.append(item)
            LOGGER.info("[户号] 获取到 %d 个户表（总共 %d 个，过滤非居民05后）",
                        len(new_list), len(result['data']['bizrt']['powerUserList']))
            self.powerUserList = new_list
            return {'errcode': 0}
        return {'errcode': 1, 'errmsg': msg}

    async def __get_door_balance(self, door_account):
        params = {
            'data': {
                'srvCode': '', 'serialNo': '',
                'channelCode': configuration['account']['channelCode'],
                'funcCode': configuration['account']['funcCode'],
                'acctId': self.userInfo['userId'],
                'userName': self.userInfo.get('loginAccount', self.userInfo.get('nickname', None)),
                'promotType': '1', 'promotCode': '1',
                'userAccountId': self.userInfo['userId'],
                'list': [{
                    'consNoSrc': door_account['consNo_dst'],
                    'proCode': door_account.get('proNo', door_account.get('provinceId', None)),
                    'sceneType': door_account.get('consSortCode', door_account.get('elecTypeCode', None)),
                    'consType': door_account.get('consType', '1'),
                    'orgNo': door_account['orgNo'],
                }],
            },
            'serviceCode': '0101143',
            'source': configuration['source'],
            'target': door_account.get('proNo', door_account.get('provinceId', None)),
        }
        result = await self.__fetch_safe(get_door_balance_api, params)
        self.handle_request_result_message('get_door_balance_api', result)
        if 'code' in result and str(result['code']) in ('1', '000000') and 'data' in result and result['data'] and 'list' in result['data']:
            balance_list = result['data']['list']
            if len(balance_list) != 0:
                door_account['account_balance'] = balance_list[0]

    async def __get_door_bill(self, door_account, year):
        params = {
            'data': {
                'acctId': self.userInfo['userId'],
                'channelCode': configuration['channelCode'],
                'getday': '11',
                'consType': door_account.get('consType', '1'),
                'funcCode': 'ALIPAY_01',
                'orgNo': door_account['orgNo'],
                'proCode': door_account['proNo'],
                'promotCode': '1', 'promotType': '1',
                'serialNo': '', 'srvCode': '',
                'userName': '',
                'provinceCode': door_account['proNo'],
                'userAccountId': self.userInfo['userId'],
                'consNo': door_account['consNo_dst'],
                'queryYear': year,
            },
            'serviceCode': 'BCP_000026',
            'source': 'app',
            'target': door_account['proNo'],
        }
        result = await self.__fetch_safe(get_door_bill_api, params)
        self.handle_request_result_message('get_door_bill_api', result)
        if 'code' in result and str(result['code']) in ('1', '000000') and 'data' in result and result['data']:
            if 'mothEleList' in result['data']:
                if 'month_bill_list' not in door_account:
                    door_account['month_bill_list'] = result['data']['mothEleList']
                else:
                    exist_map = {item['month']: item for item in door_account['month_bill_list']}
                    for item in result['data']['mothEleList']:
                        if item['month'] not in exist_map:
                            door_account['month_bill_list'].append(item)
            if 'dataInfo' in result['data']:
                return result['data']['dataInfo']

    async def __get_door_mouth_bill(self, door_account, monthBill):
        query_date = datetime.datetime.strptime(monthBill['month'], '%Y%m')
        query_str = f"{query_date.year}-{query_date.month:02d}"
        params = {
            'data': {
                'channelCode': configuration['stepelect']['channelCode'],
                'funcCode': configuration['stepelect']['funcCode'],
                'promotType': configuration['stepelect']['promotType'],
                'getday': configuration['stepelect']['getday'],
                'consNo': door_account['consNo_dst'],
                'promotCode': door_account['proNo'],
                'orgNo': door_account['orgNo'],
                'queryDate': query_str,
                'provinceCode': door_account['proNo'],
                'consType': door_account.get('consType', '1'),
                'userAccountId': self.userInfo['userId'],
                'serialNo': '', 'srvCode': '',
                'userName': self.userInfo['loginAccount'],
                'acctId': self.userInfo['userId'],
            },
            'serviceCode': configuration['stepelect']['serviceCode'],
            'source': configuration['stepelect']['source'],
            'target': door_account['proNo'],
        }
        result = await self.__fetch(get_door_ladder_api, params)
        msg = self.handle_request_result_message('get_door_ladder_api', result)
        if 'code' in result and str(result['code']) in ('1', '000000') and 'data' in result and result['data'] and 'list' in result['data']:
            data = result['data']['list'][0]
            active_count = 0
            meter_num = 0
            read_list = []

            if 'readList' in data and len(data['readList']) > 0:
                read_list = data['readList']
            elif 'pointList' in data and len(data['pointList']) > 0 and 'readList' in data['pointList'][0] and len(data['pointList'][0]['readList']) > 0:
                read_list = data['pointList'][0]['readList']

            if len(read_list) > 0:
                active_count = catchFloat(read_list[0], 'activeCount')
                if 'billRead' in read_list[0]:
                    for item in read_list[0]['billRead']:
                        meter_num = max(meter_num, catchInt(item, 'currentNumber'))

            ladder_info = {}
            ladder_info['month_meter_num'] = meter_num
            ladder_info['month_ele_num'] = normal_round(active_count, 2)
            monthBill['month_ele'] = ladder_info

    async def __get_door_daily_bill(self, door_account, year, start_date, end_date, monthBill=None):
        params = {
            'params1': {
                'serviceCode': configuration['serviceCode'],
                'source': configuration['source'],
                'target': configuration['target'],
                'uscInfo': {
                    'member': configuration['uscInfo']['member'],
                    'devciceIp': configuration['uscInfo']['devciceIp'],
                    'devciceId': configuration['uscInfo']['devciceId'],
                    'tenant': configuration['uscInfo']['tenant'],
                },
                'quInfo': {'userId': self.userInfo['userId']},
                'token': self.token,
            },
            'params3': {
                'data': {
                    'acctId': self.userInfo['userId'],
                    'consNo': door_account['consNo_dst'],
                    'consType': '1',
                    'endTime': end_date,
                    'orgNo': door_account['orgNo'],
                    'queryYear': year,
                    'proCode': door_account.get('proNo', door_account.get('provinceId', None)),
                    'serialNo': '', 'srvCode': '',
                    'startTime': start_date,
                    'userName': self.userInfo['loginAccount'],
                    'funcCode': configuration['getday']['funcCode'],
                    'channelCode': configuration['getday']['channelCode'],
                    'getday': configuration['getday']['getday'],
                    'promotCode': configuration['getday']['promotCode'],
                    'promotType': configuration['getday']['promotType'],
                },
                'serviceCode': configuration['getday']['serviceCode'],
                'source': configuration['getday']['source'],
                'target': door_account.get('proNo', door_account.get('provinceId', None)),
            },
            'params4': '010103',
        }
        result = await self.__fetch_safe(get_door_daily_bill_api, params)
        self.handle_request_result_message('get_door_daily_bill_api', result)
        if 'code' in result and str(result['code']) in ('1', '000000') and 'data' in result and result['data'] and 'sevenEleList' in result['data']:
            if monthBill is None:
                door_account['daily_bill_list'] = result['data']['sevenEleList']
            else:
                total = 0
                peak = 0
                valley = 0
                flat = 0
                sharp = 0
                for item in result['data']['sevenEleList']:
                    item['dayElePq'] = catchFloat(item, 'dayElePq')
                    item['errmsg'] = catchFloat(item, 'errmsg')
                    item['thisVPq'] = catchFloat(item, 'thisVPq')
                    item['thisNPq'] = catchFloat(item, 'thisNPq')
                    item['thisPPq'] = catchFloat(item, 'thisPPq')
                    total += item['dayElePq']
                    peak += item['errmsg']
                    valley += item['thisVPq']
                    flat += item['thisNPq']
                    sharp += item['thisPPq']
                monthBill['month_ele_num'] = normal_round(total, 2)
                monthBill['month_p_ele_num'] = normal_round(peak, 2)
                monthBill['month_v_ele_num'] = normal_round(valley, 2)
                monthBill['month_n_ele_num'] = normal_round(flat, 2)
                monthBill['month_t_ele_num'] = normal_round(sharp, 2)
                monthBill['daily_ele'] = result['data']['sevenEleList']

    # ─── 数据刷新 ───

    async def refresh_data(self, force_refresh=False):
        try:
            if force_refresh:
                await self.__get_door_number()

            should_refresh = force_refresh or int(time.time() * 1000) - self.timestamp > self.refresh_interval * 3600 * 1000
            if should_refresh is False:
                return

            now = datetime.datetime.now()
            yesterday = now - datetime.timedelta(days=1)
            end_date = f"{yesterday.year}-{yesterday.month:02d}-{yesterday.day:02d}"
            start = yesterday - datetime.timedelta(days=40)
            start_date = f"{start.year}-{start.month:02d}-{start.day:02d}"

            for account in self.powerUserList:
                try:
                    cons_no = account['consNo_dst']
                    self.doorAccountDict[cons_no] = account

                    # 获取余额
                    await self.__get_door_balance(account)
                    if self.need_login:
                        return

                    if 'account_balance' in account:
                        balance_data = account['account_balance']
                        account_balance = catchFloat(balance_data, 'accountBalance')
                        esti_amt = catchFloat(balance_data, 'estiAmt')
                        prepay_bal = catchFloat(balance_data, 'prepayBal')
                        sum_money = catchFloat(balance_data, 'sumMoney')
                        history_owe = catchFloat(balance_data, 'historyOwe')
                        cons_type = balance_data.get('consType', '1')
                        is_ment = ''
                        if 'isMent' in balance_data:
                            is_ment = balance_data['isMent']

                        is_prepaid = cons_type == '1'
                        is_postpaid = cons_type == '0'
                        is_owe = not (not is_postpaid or is_ment != '1')

                        balance = 0
                        if is_prepaid:
                            balance = sum_money
                        if is_postpaid and not is_owe:
                            balance = -abs(sum_money)
                        if is_postpaid and is_owe:
                            balance = sum_money
                        if account_balance != 0:
                            balance = account_balance
                        account['balance'] = balance

                        # 借鉴 sgcc_electricity_new: 增加预付费余额
                        if prepay_bal != 0:
                            account['prepay_balance'] = prepay_bal
                    else:
                        LOGGER.error('国家电网账户余额获取失败！')

                    if 'balance' not in account:
                        account['balance'] = 0

                    # 获取日用电量
                    await self.__get_door_daily_bill(account, now.year, start_date, end_date)
                    if 'daily_bill_list' not in account:
                        LOGGER.error('国家电网无法获取日用电数据！')
                        continue

                    # 解析日用电数据
                    valid_offset = 0
                    has_valid = False
                    for k in range(10):
                        try:
                            float(account['daily_bill_list'][k]['dayElePq'])
                            has_valid = True
                            break
                        except Exception:
                            valid_offset += 1

                    daily_total = 0
                    daily_peak = 0
                    daily_valley = 0
                    daily_flat = 0
                    daily_sharp = 0
                    account['daily_lasted_date'] = f"{now.year}-{now.month:02d}-{now.day:02d}"

                    if has_valid:
                        for k in range(valid_offset):
                            account['daily_bill_list'].pop(0)
                        latest = account['daily_bill_list'][0]
                        latest_date = datetime.datetime.strptime(latest['day'], '%Y%m%d')
                        account['daily_lasted_date'] = f"{latest_date.year}-{latest_date.month:02d}-{latest_date.day:02d}"
                        daily_total = catchFloat(latest, 'dayElePq')
                        daily_peak = catchFloat(latest, 'errmsg')
                        daily_valley = catchFloat(latest, 'thisVPq')
                        daily_flat = catchFloat(latest, 'thisNPq')
                        daily_sharp = catchFloat(latest, 'thisPPq')

                    account['daily_ele_num'] = normal_round(daily_total, 2)
                    account['daily_p_ele_num'] = normal_round(daily_peak, 2)
                    account['daily_v_ele_num'] = normal_round(daily_valley, 2)
                    account['daily_n_ele_num'] = normal_round(daily_flat, 2)
                    account['daily_t_ele_num'] = normal_round(daily_sharp, 2)

                    # 月度累计
                    month_total = 0
                    month_peak = 0
                    month_valley = 0
                    month_flat = 0
                    month_sharp = 0

                    if has_valid:
                        for item in account['daily_bill_list']:
                            item_date = datetime.datetime.strptime(item['day'], '%Y%m%d')
                            if item_date.month != latest_date.month:
                                break
                            month_total += catchFloat(item, 'dayElePq')
                            month_peak += catchFloat(item, 'errmsg')
                            month_valley += catchFloat(item, 'thisVPq')
                            month_flat += catchFloat(item, 'thisNPq')
                            month_sharp += catchFloat(item, 'thisPPq')

                    account['month_ele_num'] = normal_round(month_total, 2)
                    account['month_p_ele_num'] = normal_round(month_peak, 2)
                    account['month_v_ele_num'] = normal_round(month_valley, 2)
                    account['month_n_ele_num'] = normal_round(month_flat, 2)
                    account['month_t_ele_num'] = normal_round(month_sharp, 2)

                    # 年度数据
                    if has_valid:
                        last_month = latest_date - datetime.timedelta(days=latest_date.day)
                        if 'month_bill_list' not in account or len(account['month_bill_list']) < 12:
                            await self.__get_door_bill(account, last_month.year - 1)
                        year_data = await self.__get_door_bill(account, last_month.year)
                        if year_data is not None:
                            account['yearTotalCost'] = year_data

                        current_year_bills = []
                        if 'month_bill_list' in account:
                            for item in account['month_bill_list']:
                                if 'month_ele' not in item:
                                    await self.__get_door_mouth_bill(account, item)
                                if 'daily_ele' not in item:
                                    yr, ms, me = get_month_date_range(item['month'])
                                    e_str = f"{me.year}-{me.month:02d}-{me.day:02d}"
                                    s_str = f"{ms.year}-{ms.month:02d}-{ms.day:02d}"
                                    await self.__get_door_daily_bill(account, int(yr), s_str, e_str, item)
                                if item['month'].startswith(str(last_month.year)):
                                    current_year_bills.append(item)
                        account['year_bill_list'] = sorted(current_year_bills, key=lambda x: x['month'], reverse=True)

                    if 'yearTotalCost' in account:
                        account['year_ele_num'] = catchFloat(account['yearTotalCost'], 'totalEleNum')
                        account['year_ele_cost'] = catchFloat(account['yearTotalCost'], 'totalEleCost')
                    if 'year_ele_num' not in account:
                        account['year_ele_num'] = 0
                        account['year_ele_cost'] = 0

                    # 上月数据
                    last_month_usage = 0
                    last_month_cost = 0
                    last_month_meter = 0
                    last_bill_date = yesterday

                    if 'year_bill_list' in account and len(account['year_bill_list']) > 0:
                        latest_bill = account['year_bill_list'][0]
                        account['last_month_ele_num'] = catchFloat(latest_bill, 'monthEleNum')
                        account['last_month_ele_cost'] = catchFloat(latest_bill, 'monthEleCost')
                        if 'month_ele' in latest_bill:
                            last_month_meter = latest_bill['month_ele']['month_meter_num']
                        last_bill_date = datetime.datetime.strptime(latest_bill['month'], '%Y%m')

                    if 'last_month_ele_num' not in account:
                        account['last_month_ele_num'] = 0
                        account['last_month_ele_cost'] = 0

                    account['last_month_meter_num'] = int(last_month_meter)

                    # 年度累计（从月账单汇总）
                    year_total = 0
                    year_peak = 0
                    year_valley = 0
                    year_flat = 0
                    year_sharp = 0

                    if last_bill_date.month == 12:
                        year_total = account['month_ele_num']
                        year_peak = account['month_p_ele_num']
                        year_valley = account['month_v_ele_num']
                        year_flat = account['month_n_ele_num']
                        year_sharp = account['month_t_ele_num']
                    else:
                        if 'year_bill_list' in account:
                            for bill in account['year_bill_list']:
                                year_total += catchFloat(bill, 'monthEleNum')
                                year_peak += bill.get('month_p_ele_num', 0)
                                year_valley += bill.get('month_v_ele_num', 0)
                                year_flat += bill.get('month_n_ele_num', 0)
                                year_sharp += bill.get('month_t_ele_num', 0)
                        if has_valid and latest_date.month != last_bill_date.month:
                            year_total += account['month_ele_num']
                            year_peak += account['month_p_ele_num']
                            year_valley += account['month_v_ele_num']
                            year_flat += account['month_n_ele_num']
                            year_sharp += account['month_t_ele_num']

                    account['year_ele_num'] = normal_round(year_total, 2)
                    account['year_p_ele_num'] = normal_round(year_peak, 2)
                    account['year_v_ele_num'] = normal_round(year_valley, 2)
                    account['year_n_ele_num'] = normal_round(year_flat, 2)
                    account['year_t_ele_num'] = normal_round(year_sharp, 2)

                    # 最近30天日用电列表
                    if 'daily_bill_list' in account:
                        daily_list = []
                        for item in account['daily_bill_list'][:30]:
                            daily_list.append({
                                'day': item['day'],
                                'ele': normal_round(catchFloat(item, 'dayElePq'), 2),
                                'v_ele': normal_round(catchFloat(item, 'thisVPq'), 2),
                                'p_ele': normal_round(catchFloat(item, 'errmsg'), 2),
                                'n_ele': normal_round(catchFloat(item, 'thisNPq'), 2),
                                't_ele': normal_round(catchFloat(item, 'thisPPq'), 2),
                            })
                        daily_list.reverse()
                        account['recent_30_daily_ele_list'] = daily_list
                    else:
                        account['recent_30_daily_ele_list'] = []

                    # 最近12个月月用电列表
                    if 'month_bill_list' in account:
                        account['month_bill_list'] = sorted(
                            account['month_bill_list'], key=lambda x: x['month'], reverse=True
                        )
                        monthly_list = []
                        for item in account['month_bill_list'][:12]:
                            monthly_list.append({
                                'month': item['month'],
                                'cost': normal_round(catchFloat(item, 'monthEleCost'), 2),
                                'ele': normal_round(catchFloat(item, 'monthEleNum'), 2),
                                'v_ele': item.get('month_v_ele_num', 0),
                                'p_ele': item.get('month_p_ele_num', 0),
                                'n_ele': item.get('month_n_ele_num', 0),
                                't_ele': item.get('month_t_ele_num', 0),
                            })
                        monthly_list.reverse()
                        account['recent_12_monthly_ele_list'] = monthly_list
                    else:
                        account['recent_12_monthly_ele_list'] = []

                    account['refresh_time'] = datetime.datetime.strftime(now, '%Y-%m-%d %H:%M:%S')

                except Exception as account_ex:
                    cons_no = account.get('consNo_dst', '?')
                    LOGGER.exception("[数据刷新] 户号 %s 刷新失败: %s", cons_no, account_ex)
                    continue

            await self.save_data()
        except Exception as ex:
            LOGGER.exception("刷新数据异常: %s", ex)
            return 0

    def get_door_account_list(self):
        return list(self.doorAccountDict.values())

    def get_door_account(self):
        return self.doorAccountDict
