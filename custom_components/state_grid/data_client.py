"""
国家电网数据客户端 - Merged Version

基于 bilezhou/sgcc_electricity_new 原版（数据获取逻辑），合并登录增强功能:
1. 支持点选验证码（LLM 视觉大模型识别）
2. 支持滑块验证码（LLM + 像素算法双模式）
3. 自动检测验证码类型
4. 增加 LLM 配置（API Key, Base URL, Model）
5. RK001冷却机制（密码登录日额度用完后不再无效重试）
6. 邮箱降级登录（RK001是账号维度的限流，手机号限流后邮箱仍可登录）
7. 保留 bilezhou 原版数据获取逻辑（混淆变量名、refresh_data等）
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

# ─── bilezhou 原版混淆变量映射 ───
_Au='daily_ele'
_At='month_meter_num'
_As='constType'
_Ar='queryYear'
_Aq='provinceCode'
_Ap='redirect_url'
_Ao='refresh_interval'
_An='dataVersion'
_Am='doorAccountDict'
_Al='refreshToken'
_Ak='accessToken'
_Aj='brightness'
_Ai='BCP_00026'
_Ah='serviceCode_smt'
_Ag='WEBA10070900'
_Af='serviceType'
_Ae='jM_custType'
_Ad='jM_busiTypeCode'
_Ac='doorNumberManeger'
_Ab='proCode'
_Aa='loginAccount'
_AZ='userAccountId'
_AY='elecTypeCode'
_AX='quInfo'
_AW='blockY'
_AV='blockSrc'
_AU='canvasSrc'
_AT='powerUserList'
_AS='userInfo'
_AR='publicKey'
_AQ='WEBA10070800'
_AP='timeDay'
_AO='WEBA10070700'
_AN='state_grid'
_AM='channelNo'
_AL='month_ele'
_AK='consType'
_AJ='provinceId'
_AI='userName'
_AH='acctId'
_AG='bizrt'
_AF='password'
_AE='0101046'
_AD='month_ele_num'
_AC='consNo'
_AB='list'
_AA='token'
_A9='keyCode'
_A8='querytypeCode'
_A7='01010049'
_A6='month_t_ele_num'
_A5='month_n_ele_num'
_A4='month_v_ele_num'
_A3='month_p_ele_num'
_A2='thisTPq'
_A1='thisNPq'
_A0='thisVPq'
_z='thisPPq'
_y='errmsg'
_x='BCP_000026'
_w='app'
_v='WEBALIPAY_01'
_u='order'
_t='dayElePq'
_s='timestamp'
_r='authFlag'
_q='09'
_p='0101183'
_o='tenant'
_n='devciceId'
_m='devciceIp'
_l='member'
_k='stepelect'
_j='account'
_i='daily_bill_list'
_h='orgNo'
_g='consNo_dst'
_f='srvrt'
_e='0101154'
_d='getday'
_c='clearCache'
_b='promotCode'
_a='01'
_Z='month'
_Y='account_balance'
_X='proNo'
_W='userId'
_V=True
_U='SGAPP'
_T='target'
_S='month_bill_list'
_R='promotType'
_Q='uscInfo'
_P='subBusiTypeCode'
_O='serialNo'
_N=False
_M='0902'
_L='srvCode'
_K='serCat'
_J='busiTypeCode'
_I='code'
_H='channelCode'
_G='errcode'
_F='1'
_E='source'
_D=None
_C='serviceCode'
_B='funcCode'
_A='data'

# ─── API 常量 ───
appKey='7e5b5e84ddad4994b0ebc68dedca4962'
appSecret='2bc37a881e1541aaa6e6e174658d150b'
baseApi='https://www.95598.cn/api'
get_request_key_api='/oauth2/outer/c02/f02'
get_request_authorize_api='/oauth2/oauth/authorize'
get_web_token_api='/oauth2/outer/getWebToken'
get_verify_code_api='/osg-web0004/open/c44/f05'
verify_password_api='/osg-web0004/open/c44/f06'
click_card_api='/osg-web0004/open/c44/f07'
get_door_number_api='/osg-open-uc0001/member/c9/f02'
get_door_balance_api='/osg-open-bc0001/member/c05/f01'
get_door_bill_api='/osg-open-bc0001/member/c01/f02'
get_door_ladder_api='/osg-open-bc0001/member/c04/f03'
get_door_daily_bill_api='/osg-web0004/member/c24/f01'
sessionIdControlApiList=[verify_password_api,get_verify_code_api,click_card_api]
keyCodeControlApiList=[verify_password_api,get_verify_code_api,get_request_authorize_api,get_web_token_api,get_door_number_api,get_door_balance_api,get_door_bill_api,get_door_ladder_api,get_door_daily_bill_api,click_card_api]
authControlApiList=[get_door_number_api,get_door_balance_api,get_door_bill_api,get_door_ladder_api,get_door_daily_bill_api]
tControlApiList=[get_door_number_api,get_door_balance_api,get_door_bill_api,get_door_ladder_api,get_door_daily_bill_api]

# ─── bilezhou 原版业务配置 ───
configuration={_Q:{_l:_M,_m:'',_n:'',_o:_AN},_E:_U,_T:'32101',_H:_M,_AM:_M,'toPublish':_a,'siteId':'2012000000033700',_L:'',_O:'',_B:'',_C:{_u:_e,'uploadPic':'0101296','pauseSCode':'0101250','pauseTCode':'0101251','listconsumers':'0101093','messageList':'0101343','submit':'0101003','sbcMsg':'0101210','powercut':'0104514','BkAuth01':'f15','BkAuth02':'f18','BkAuth03':'f02','BkAuth04':'f17','BkAuth05':'f05','BkAuth06':'f16','BkAuth07':'f01','BkAuth08':'f03'},'electricityArchives':{'servicecode':'0104505',_E:_M},'subscriptionList':{_L:'APP_SGPMS_05_030',_O:'22',_H:_M,_B:'22',_T:'-1'},'userInformation':{_C:'01008183',_E:_U},'userInform':{_C:_p,_E:_U},'elesum':{_H:_M,_B:_v,_b:_F,_R:_F,_C:'0101143',_E:_w},_j:{_H:_M,_B:'WEBA1007200'},_Ac:{_E:_M,_T:'-1',_H:_q,_AM:_q,_C:_A7,_B:'WEBA40050000',_Q:{_l:_M,_m:'',_n:'',_o:_AN}},'doorAuth':{_E:_U,_C:'f04'},'xinZ':{_K:'101',_Ad:'101','fJ_busiTypeCode':'102',_Ae:'03','fJ_custType':'02',_Af:_a,_P:'',_B:_AO,_u:_e,_E:_U,_A8:_F},'onedo':{_C:_AE,_E:_U,_B:_AO,'queryType':'03'},'xinHuTongDian':{_K:'110',_J:'211',_P:'21102',_B:'WEBA10071200',_H:_M,_E:_q,_C:_p},'company':{_K:'104',_B:_AO,_Af:'02',_A8:_F,_r:_F,_E:_U,_u:_e},'charge':{_H:_q,_B:'WEBA10071300',_AM:'0901',_K:'102',_Ae:_a,_Ad:'102'},'other':{_H:_q,_B:'WEBA10079700',_K:'129',_J:'999',_P:'21501',_C:_x,_L:'',_O:''},'vatchange':{'submit':'0101003',_J:'320',_P:'',_K:'115',_B:'WEBA10074000',_r:_F},'bill':{_c:_F,_B:_v,_R:_F,_C:_x},_k:{_H:_M,_B:_v,_R:_F,_c:_q,_C:_x,_E:_w},_d:{_H:_M,_c:'11',_B:_v,_b:_F,_R:_F,_C:_x,_E:_w},'mouthOut':{_H:_M,_c:'11',_B:_v,_b:_F,_R:_F,_C:_x,_E:_w},'meter':{_K:'114',_J:'304',_B:'WEBA10071000',_P:'',_C:_AE,_O:''},'complaint':{_J:'005','srvMode':_M,'anonymousFlag':'0','replyMode':_a,'retvisitFlag':_a},'report':{_J:'006'},'tradewinds':{_J:'019'},'somesay':{_J:'091'},'faultrepair':{_B:_Ag,_C:_p,_K:'111',_J:'001',_P:'21505'},'electronicInvoice':{_K:'105',_J:'0'},'rename':{_C:_AE,_B:'WEBA10076100',_J:'210',_K:'109',_r:_F,'gh_busiTypeCode':'211','gh_subusi':'21101',_O:'',_L:''},'pause':{_P:'',_C:_A7,_B:'WEBA10073600',_K:'107',_J:'203','jr_busi':'201',_O:'',_L:''},'capacityRecovery':{_C:_A7,_E:_U,_L:'',_O:'',_B:'WEBA10073700','busiTypeCode_stop':'204','busiTypeCode_less':'202',_J:'202',_P:'',_K:'108',_AP:'5',_r:_F},'electricityPriceChange':{_C:_p,_J:'215',_P:'21502',_K:'113',_r:_F,_AP:'15',_B:'WEBA10073900WEB',_L:'',_O:''},'electricityPriceStrategyChange':{_C:'01008183',_J:'215',_P:'21506',_K:'160',_B:'WEBV00000517WEB',_L:'',_O:''},'eemandValueAdjustment':{_C:_p,_L:'',_O:'',_K:'112',_B:'WEBA10073800',_J:'215',_P:'21504',_r:_F,_AP:'5','getMonthServiceCode':_AE},'businessProgress':{_C:_p,_L:_a,_B:'WEB01'},'increase':{_E:_U,_O:'',_L:'',_Ah:_A7,_C:_e,_u:_e,_B:_AQ,_A8:_F,_K:'106',_J:'111',_P:''},'fjincrea':{_K:'105',_J:'110',_P:'',_E:_U,_B:_AQ,_O:'',_L:'',_Ah:_A7,_C:_e,_u:_e,_A8:_F},'persIncrea':{_K:'105',_J:'109',_u:_e,_P:'',_E:_U,_B:_AQ,_A8:_F},'fgdChange':{_C:_p,_L:_a,_H:_q,_B:_Ag,_J:'215',_P:'21505',_K:'111',_r:_F},'createOrder':{_H:_M,_B:_v,_L:'BCP_000001','chargeMode':'02','conType':_a,'bizTypeId':'BT_ELEC'},'largePopulation':{_J:'383',_B:'WEBA10076800',_P:'',_L:'',_R:'',_b:'',_H:'0901',_K:'383',_C:'',_O:''},'biaoJiCode':{_C:'0104507',_E:'1704',_H:'1704'},'twoGuar':{_J:'402',_P:'40201',_B:'web_twoGuar'},'electTrend':{_C:_Ai,_H:_M},'emergency':{_C:_Ai,_B:'A10000000',_H:_M},'infoPublic':{_C:'2545454',_E:_w}}

# ─── bilezhou 原版工具函数 ───
def json_dumps(data):return json.dumps(data,separators=(',',':'),ensure_ascii=_N)
def normal_round(num,ndigits=0):
        A=ndigits
        if A==0:return int(num+.5)
        else:B=10**A;return int(num*B+.5)/B
def catchFloat(data,key):
        if key in data:
                try:return normal_round(float(data[key]),2)
                except:return 0
        else:return 0
def catchInt(data,key):
        if key in data:
                try:return normal_round(float(data[key]),0)
                except:return 0
        else:return 0
def get_month_date_range(date_str):
        C=date_str;A=int(C[:4]);B=int(C[4:]);F=datetime.date(A,B,1)
        if B==12:D=1;E=A+1
        else:D=B+1;E=A
        G=datetime.date(E,D,1)-datetime.timedelta(days=1);return A,F,G
def base64_image_to_bytes(base64_data):
        A=base64_data
        if A.startswith('data:image'):
                B=A.find(',')
                if B!=-1:A=A[B+1:]
        C=base64.b64decode(A);return C
def is_dark(pixel,threshold=100,method=_Aj):
        F=pixel;D=method
        if len(F)==4:
                A,B,C,G=F
                if G<128:return _N
        else:A,B,C=F
        if D==_Aj:H=max(A,B,C);I=min(A,B,C);E=H
        elif D=='average':E=(A+B+C)//3
        elif D=='max':E=max(A,B,C)
        elif D=='perceived':E=int(.299*A+.587*B+.114*C)
        else:raise ValueError(f"未知方法: {D}")
        return E<threshold
def find_max_rectangle(matrix):
        C=matrix
        if not C or not C[0]:return 0,0,0,0
        L,E=len(C),len(C[0]);D=[0]*E;G=0;H=0,0,0,0
        for F in range(L):
                for A in range(E):
                        if C[F][A]==1:D[A]+=1
                        else:D[A]=0
                B=[]
                for A in range(E+1):
                        M=D[A]if A<E else-1
                        while B and M<D[B[-1]]:
                                N=B.pop();I=D[N];J=A if not B else A-B[-1]-1;K=I*J
                                if K>G:G=K;O=F-I+1;P=A-J;Q=F;R=A-1;H=O,P,Q,R
                        B.append(A)
        return H

class StateGridDataClient:
        hass=_D;coordinator=_D;session=_D;dataVersion=_D;keyCode=_D;publicKey=_D;need_login=_N;phone=_D;codeKey=_D;serialNo=_D;qrCodeSerial=_D;userInfo=_D;accountInfo=_D;powerUserList=_D;doorAccountDict={};cookie=[];timestamp=int(time.time()*1000);accessToken=_D;refreshToken=_D;token=_D;expirationDate=_D;refresh_interval=8;is_debug=_N;shown_notification=_N

        # LLM 配置
        llm_api_key = ""
        llm_base_url = "https://ark.cn-beijing.volces.com/api/v3"
        llm_model = "doubao-seed-2-0-pro-260215"

        # 备用邮箱（RK001降级用）
        email_account = ""

        # RK001 冷却时间戳（手机号密码登录日额度用完后，避免无效重试）
        _rk001_cooldown_until = 0.0

        # ─── 增强版 __init__（来自 fork） ───
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

        # ─── 增强版 save_data（来自 fork） ───
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

        # ─── bilezhou 原版加密方法（不变） ───
        def encrypt_post_data(A,data):B={'_access_token':A.accessToken[len(A.accessToken)//2:]if A.accessToken else'','_t':A.token[len(A.token)//2:]if A.token else'','_data':data,_s:A.timestamp};return A.encrypt_wapper_data(B)
        def encrypt_wapper_data(A,data):B=a(json_dumps(data),A.keyCode);return{_A:B+c(B+str(A.timestamp)),'skey':d(A.keyCode,A.publicKey),_s:str(A.timestamp)}
        def handle_request_result_message(E,api,result,printResult=_V):
                D='message';C='resultMessage';A=result
                if E.is_debug and printResult:LOGGER.warning(api+'-'+json_dumps(A))
                B=_D
                if _A in A and A[_A]and _f in A[_A]and C in A[_A][_f]:B=A[_A][_f][C]
                elif _f in A and C in A[_f]:B=A[_f][C]
                elif D in A:B=A[D]
                else:B=json_dumps(A)
                return B

        # ─── 增强版 __fetch_safe（来自 fork，含RK001流控检测） ───
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

        # ─── 增强版 __need_login（来自 fork，11401不触发常规重新登录） ───
        def __need_login(self, code):
                # 11401=RK001限流（不触发常规重新登录，应由流控降级处理）
                if code in (11401,):
                        return False
                if code in (10015, 10108, 10009, 10207, 10005, 10010, 30010, 10002):
                        self.need_login = True
                        return True
                return False

        # ─── 增强版 __try_password_login（来自 fork，含RK001冷却） ───
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

        # ─── bilezhou 原版 __fetch（不变） ───
        async def __fetch(A,api,data,header=_D):
                R='encryptData';Q='client_secret';P='application/json;charset=UTF-8';O='Content-Type';M=header;J='client_id';D=api;A.timestamp=int(time.time()*1000);E=A.timestamp
                if A.keyCode is _D:A.keyCode=e(32,16,2)
                G=A.keyCode;F={'Accept':P,O:P,'version':'1.0',_E:'0901',_s:str(E),'wsgwType':'web','appKey':appKey};C=data
                if D==get_request_key_api:C={J:appKey,Q:appSecret};H=a(json_dumps(C),G);C={_A:H+c(H+str(E)),'skey':d(G,'042D12DFBC179202AC4B7B7BADCDA6FF7B604339263F6AB732CE7107B7EA3830A2CA714DC303920D3CFF7647D898F1A8CC6C24E9EC3CC194E22D984AF7E16B42DC'),J:appKey,_s:str(E)}
                elif D==get_request_authorize_api:
                        C={J:appKey,'response_type':_I,_Ap:'/test',_s:E,'rsi':A.token};C=urllib.parse.urlencode(C);F[O]='application/x-www-form-urlencoded; charset=UTF-8';F[_A9]=G;K=async_get_clientsession(A.hass,_N)
                        async with K.post(baseApi+D,data=C,headers=F)as L:B=await L.json();B=b(B[_A],A.token);B=json.loads(B);return B
                elif D==get_web_token_api:C={'grant_type':'authorization_code','sign':c(appKey+str(E)),Q:appSecret,'state':'464606a4-184c-4beb-b442-2ab7761d0796','key_code':G,J:appKey,_s:E,_I:C[_I]};H=a(json_dumps(C),G);C={_A:H+c(H+str(E)),'skey':d(G,A.publicKey),_s:str(E)}
                else:C=A.encrypt_post_data(C)
                if M is not _D:F.update(M)
                if D in sessionIdControlApiList:F['sessionId']='web'+str(E)
                if D in keyCodeControlApiList:F[_A9]=G
                if D in authControlApiList:F['Authorization']='Bearer '+A.accessToken[:len(A.accessToken)//2]
                if D in tControlApiList:F['t']=A.token[:len(A.token)//2]
                I=0
                while I<MAX_RETRIES:
                        try:
                                K=async_get_clientsession(A.hass,_N)
                                async with K.post(baseApi+D,json=C,headers=F)as L:
                                        B=await L.text()
                                        if B.startswith('{'):
                                                B=json.loads(B)
                                                if R in B:B=b(B[R],G);B=json.loads(B)
                                        return B
                        except Exception as N:
                                LOGGER.error(f"请求错误: {N}. 尝试第 {I+1} 次重试...");I+=1
                                if I==MAX_RETRIES:raise N

        # ─── bilezhou 原版 __get_request_key（不变） ───
        async def __get_request_key(A):
                A.keyCode=_D;B=await A.__fetch(get_request_key_api,{});C=A.handle_request_result_message('get_request_key_api',B)
                if B[_I]==_F:A.keyCode=B[_A][_A9];A.publicKey=B[_A][_AR];return{_G:0}
                return{_G:1,_y:C}

        # ─── 增强版 __get_pass_verify_code（来自 fork，支持滑块+点选） ───
        async def __get_pass_verify_code(self, account, password):
                """获取验证码，支持滑块和点选两种类型。"""
                params = {
                        'account': account,
                        'password': password,
                        'canvasHeight': 200,
                        'canvasWidth': 310,
                }
                result = await self.__fetch(get_verify_code_api, params)
                msg = self.handle_request_result_message('get_verify_code_api', result, _N)

                # API 返回的 code 可能是 int 1 或 str '1'，统一用 str 比较
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

        # ─── 增强版 __verify_password（来自 fork，支持captcha_type） ───
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
                                        'optSys': 'ios', 'pushId': '00000',
                                        'addressProvince': '110100', 'password': password,
                                        'addressRegion': '110101', 'account': account,
                                        'addressCity': '330100',
                                },
                        },
                        'Channels': 'web',
                }

                # 根据验证码类型添加 complexSliderRet 和 complexSliderType 字段
                if captcha_type == 'click':
                        params['complexSliderRet'] = 0
                        params['complexSliderType'] = 'clickImg'
                elif captcha_type == 'slider':
                        params['complexSliderRet'] = 0
                        params['complexSliderType'] = 'blockPuzzle'

                # 调试日志
                LOGGER.info(f"提交验证码: type={captcha_type}, code_type={type(code).__name__}, code={code}, loginKey={loginKey[:20] if loginKey else 'None'}...")

                result = await self.__fetch(verify_password_api, params)
                msg = self.handle_request_result_message('verify_password_api', result)
                LOGGER.debug(f"验证密码结果: code={result.get('code')}, msg={msg}")

                # API 返回的 code 可能是 int 1 或 str '1'，统一用 str 比较
                if 'code' in result and str(result['code']) == '1':
                        if result['data'] and result['data'].get('srvrt') and result['data']['srvrt'].get('resultCode') == '0000':
                                self.token = result['data']['bizrt']['token']
                                self.userInfo = result['data']['bizrt']['userInfo'][0]
                                return {'errcode': 0}

                # 保留原始错误码，便于流控检测
                raw_code = result.get('code')
                return {'errcode': 1, 'errmsg': msg, 'raw_code': raw_code}

        # ─── 新增 __verify_click_captcha（来自 fork，点选验证码f07端点） ───
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

                # API 返回的 code 可能是 int 1 或 str '1'，统一用 str 比较
                if 'code' in result and str(result['code']) == '1':
                        if result['data'] and result['data'].get('srvrt') and result['data']['srvrt'].get('resultCode') == '0000':
                                self.token = result['data']['bizrt']['token']
                                self.userInfo = result['data']['bizrt']['userInfo'][0]
                                return {'errcode': 0}

                LOGGER.warning(f"clickCard(f07) 验证失败: {msg}，尝试回退到 f06 + complexSliderType...")
                # 保留原始错误码，便于流控检测
                raw_code = result.get('code')
                return {'errcode': 1, 'errmsg': msg, 'raw_code': raw_code}

        # ─── bilezhou 原版 __get_request_authorize（不变） ───
        async def __get_request_authorize(B):
                A=await B.__fetch(get_request_authorize_api,{});E=B.handle_request_result_message('get_request_authorize_api',A)
                if _I in A and A[_I]==_F:C=A[_A][_Ap];D=C.rfind('code=');B.authorizeCode=C[D+5:D+5+32];return{_G:0}
                return{_G:1,_y:E}

        # ─── bilezhou 原版 __get_web_token（不变） ───
        async def __get_web_token(A):
                C={_I:A.authorizeCode};B=await A.__fetch(get_web_token_api,C);D=A.handle_request_result_message('get_web_token_api',B)
                if _I in B and B[_I]==_F:A.accessToken=B[_A]['access_token'];A.refreshToken=B[_A]['refresh_token'];return{_G:0}
                return{_G:1,_y:D}

        # ─── 验证码解算方法（来自 fork） ───

        def _solve_slider_captcha_pixel(self, captcha_data: dict) -> int:
                """使用像素算法解算滑块验证码（bilezhou原版逻辑，作为 LLM 的后备方案）。"""
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
                for y_idx in range(h):
                        for x_idx in range(w):
                                pixel = binary.getpixel((x_idx, y_idx))
                                if is_dark(pixel, 100):
                                        matrix[x_idx][y_idx] = 1
                                else:
                                        matrix[x_idx][y_idx] = 0

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
                                icons = captcha_data[_F_iconSrcs]
                                if isinstance(icons, list) and len(icons) > 0:
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
                        coord_str = "|".join([f"{x},{y}" for x, y in coords])
                        LOGGER.info(f"点选验证码坐标: {coord_str}")
                        return coord_str

                except NotImplementedError:
                        raise
                except Exception as ex:
                        LOGGER.exception("点选验证码解算失败: %s", ex)
                        return ""

        # ─── 流控检测方法（来自 fork） ───

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

        # ─── 增强版 password_login（来自 fork，支持滑块+点选验证码） ───
        async def password_login(self, account, password, encode=False, retry=0):
                """账号密码登录。

                注意: RK001(11401)是账号维度的密码登录日额度限制。
                手机号被限流后，邮箱账号仍可正常登录（自动降级）。
                """
                # RK001 冷却期内，不再尝试手机号密码登录
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
                                # 点选验证码 - 使用 LLM 解算
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

        # ─── 邮箱降级登录方法（来自 fork） ───

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

                        # 步骤3: 解算验证码
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
                                LOGGER.error("[邮箱降级] 验证码解算遇到 NotImplementedError: %s", nie)
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
                        self.account = self.email_account
                        self.password = pwd
                        LOGGER.info("[邮箱降级] 邮箱登录验证通过，正在获取token...")
                        return await self.__get_token()

                except Exception as ex:
                        LOGGER.exception("[邮箱降级] 登录异常: %s (type=%s)", ex, type(ex).__name__)
                        return {'errcode': 1, 'errmsg': f'邮箱降级登录异常: {ex}'}

        # ─── bilezhou 原版 __get_token（不变） ───
        async def __get_token(B):
                A=await B.__get_request_authorize()
                if _G in A and A[_G]!=0:return A
                A=await B.__get_web_token()
                if _G in A and A[_G]!=0:return A
                B.need_login=_N;await B.save_data();return{_G:0}

        # ─── 增强版 _show_token_notification（来自 fork，支持自定义消息） ───
        def _show_token_notification(self, msg=None):
                if self.shown_notification:
                        return
                self.shown_notification = True
                import persistent_notification
                if msg is None:
                        msg = '国家电网登录失败，将在下个轮询重试'
                persistent_notification.create(self.hass, msg, title='国家电网 - 登录失败')
                LOGGER.error(msg)

        # ─── bilezhou 原版 __get_door_number（不变） ───
        async def __get_door_number(A):
                B=configuration[_Ac];G={_C:B[_C],_E:B[_E],_T:B[_T],_Q:{_l:B[_Q][_l],_m:B[_Q][_m],_n:B[_Q][_n],_o:B[_Q][_o]},_AX:{_W:A.userInfo[_W]},_AA:A.token};C=await A.__fetch_safe(get_door_number_api,G);H=A.handle_request_result_message('get_door_number_api',C)
                if _I in C and str(C[_I]) in ('1', '0000', '000000') and _A in C and _AG in C[_A]:
                        E={}
                        if A.powerUserList is not _D:E={A[_g]:A for A in A.powerUserList}
                        F=[]
                        for D in C[_A][_AG][_AT]:
                                if D[_g]in E:F.append(E[D[_g]])
                                elif _AY in D and D[_AY]!='05':F.append(D)
                        A.powerUserList=F;return{_G:0}
                return{_G:1,_y:H}

        # ─── bilezhou 原版 __get_door_balance（不变） ───
        async def __get_door_balance(C,door_account):
                A=door_account;E={_A:{_L:'',_O:'',_H:configuration[_j][_H],_B:configuration[_j][_B],_AH:C.userInfo[_W],_AI:C.userInfo.get(_Aa,C.userInfo.get('nickname',_D)),_R:_F,_b:_F,_AZ:C.userInfo[_W],_AB:[{'consNoSrc':A[_g],_Ab:A.get(_X,A.get(_AJ,_D)),'sceneType':A.get('consSortCode',A.get(_AY,_D)),_AC:A[_AC],_h:A[_h]}]},_C:'0101143',_E:configuration[_E],_T:A.get(_X,A.get(_AJ,_D))};B=await C.__fetch_safe(get_door_balance_api,E);C.handle_request_result_message('get_door_balance_api',B)
                if _I in B and str(B[_I]) in ('1', '000000') and _A in B and B[_A]and _AB in B[_A]:
                        D=B[_A][_AB]
                        if len(D)!=0:A[_Y]=D[0]

        # ─── bilezhou 原版 __get_door_bill（不变） ───
        async def __get_door_bill(C,door_account,year):
                F='dataInfo';D='mothEleList';A=door_account;G={_A:{_AH:C.userInfo[_W],_H:configuration[_H],_c:'11',_AK:A[_As],_B:'ALIPAY_01',_h:A[_h],_Ab:A[_X],_b:_F,_R:_F,_O:'',_L:'',_AI:'',_Aq:A[_X],_AZ:C.userInfo[_W],_AC:A[_g],_Ar:year},_C:_x,_E:_w,_T:A[_X]};B=await C.__fetch_safe(get_door_bill_api,G);C.handle_request_result_message('get_door_bill_api',B)
                if _I in B and str(B[_I]) in ('1', '000000') and _A in B and B[_A]:
                        if D in B[_A]:
                                if _S not in A:A[_S]=B[_A][D]
                                else:
                                        H={A[_Z]:A for A in A[_S]};I=B[_A][D]
                                        for E in I:
                                                if E[_Z]not in H:A[_S].append(E)
                        if F in B[_A]:return B[_A][F]

        # ─── bilezhou 原版 __get_door_mouth_bill（不变） ───
        async def __get_door_mouth_bill(F,door_account,monthBill):
                M='billRead';J=monthBill;G='pointList';E='readList';C=door_account;K=datetime.datetime.strptime(J[_Z],'%Y%m');N=f"{K.year}-{K.month:02d}";O={_A:{_H:configuration[_k][_H],_B:configuration[_k][_B],_R:configuration[_k][_R],_c:configuration[_k][_c],_AC:C[_g],_b:C[_X],_h:C[_h],'queryDate':N,_Aq:C[_X],_AK:C[_As],_AZ:F.userInfo[_W],_O:'',_L:'',_AI:F.userInfo[_Aa],_AH:F.userInfo[_W]},_C:configuration[_k][_C],_E:configuration[_k][_E],_T:C[_X]};B=await F.__fetch(get_door_ladder_api,O);Q=F.handle_request_result_message('get_door_ladder_api',B)
                if _I in B and str(B[_I]) in ('1', '000000') and _A in B and B[_A]and _AB in B[_A]:
                        A=B[_A][_AB][0];H=0;L=0;D=[]
                        if E in A and len(A[E])>0:D=A[E]
                        elif G in A and len(A[G])>0 and E in A[G][0]and len(A[G][0][E])>0:D=A[G][0][E]
                        if len(D)>0:
                                L=catchFloat(D[0],'activeCount')
                                if M in D[0]:
                                        for P in D[0][M]:H=max(H,catchInt(P,'currentNumber'))
                        I={};I[_At]=H;I[_AD]=normal_round(L,2);J[_AL]=I

        # ─── bilezhou 原版 __get_door_daily_bill（不变） ───
        async def __get_door_daily_bill(E,door_account,year,start_date,end_date,monthBill=_D):
                F='sevenEleList';D=monthBill;C=door_account;L={'params1':{_C:configuration[_C],_E:configuration[_E],_T:configuration[_T],_Q:{_l:configuration[_Q][_l],_m:configuration[_Q][_m],_n:configuration[_Q][_n],_o:configuration[_Q][_o]},_AX:{_W:E.userInfo[_W]},_AA:E.token},'params3':{_A:{_AH:E.userInfo[_W],_AC:C[_g],_AK:_a,'endTime':end_date,_h:C[_h],_Ar:year,_Ab:C.get(_X,C.get(_AJ,_D)),_O:'',_L:'','startTime':start_date,_AI:E.userInfo[_Aa],_B:configuration[_d][_B],_H:configuration[_d][_H],_c:configuration[_d][_c],_b:configuration[_d][_b],_R:configuration[_d][_R]},_C:configuration[_d][_C],_E:configuration[_d][_E],_T:C.get(_X,C.get(_AJ,_D))},'params4':'010103'};B=await E.__fetch_safe(get_door_daily_bill_api,L);E.handle_request_result_message('get_door_daily_bill_api',B)
                if _I in B and str(B[_I]) in ('1', '000000') and _A in B and B[_A]and F in B[_A]:
                        if D is _D:C[_i]=B[_A][F]
                        else:
                                G=0;H=0;I=0;J=0;K=0
                                for A in B[_A][F]:A[_t]=catchFloat(A,_t);A[_z]=catchFloat(A,_z);A[_A0]=catchFloat(A,_A0);A[_A1]=catchFloat(A,_A1);A[_A2]=catchFloat(A,_A2);G+=A[_t];H+=A[_z];I+=A[_A0];J+=A[_A1];K+=A[_A2]
                                D[_AD]=normal_round(G,2);D[_A3]=normal_round(H,2);D[_A4]=normal_round(I,2);D[_A5]=normal_round(J,2);D[_A6]=normal_round(K,2);D[_Au]=B[_A][F]

        # ─── bilezhou 原版 refresh_data（不变，已移除调试print） ───
        async def refresh_data(C,force_refresh=_N):
                A5='recent_12_monthly_ele_list';A4='recent_30_daily_ele_list';A3='monthEleCost';A2='last_month_ele_cost';A1='year_ele_cost';A0='%Y%m%d';z='daily_lasted_date';y='isMent';f=force_refresh;e='monthEleNum';d='last_month_ele_num';T='year_ele_num';S='yearTotalCost';R='day';J='year_bill_list';I='balance'
                try:
                        if f:await C.__get_door_number()
                        A6=f or int(time.time()*1000)-C.timestamp>C.refresh_interval*3600*1000
                        if A6 is _N:return
                        H=datetime.datetime.now();D=H-datetime.timedelta(days=1);U=f"{D.year}-{D.month:02d}-{D.day:02d}";F=D-datetime.timedelta(days=40);V=f"{F.year}-{F.month:02d}-{F.day:02d}"
                        for A in C.powerUserList:
                                A7=A[_g];C.doorAccountDict[A7]=A;await C.__get_door_balance(A)
                                if C.need_login is _V:return
                                if _Y in A:
                                        g=catchFloat(A[_Y],'accountBalance');AB=catchFloat(A[_Y],'estiAmt');AC=catchFloat(A[_Y],'prepayBal');W=catchFloat(A[_Y],'sumMoney');AD=catchFloat(A[_Y],'historyOwe');h=A[_Y][_AK];i=''
                                        if y in A[_Y]:i=A[_Y][y]
                                        A8=h==_F;X=h=='0';j=not(not X or i!=_F)
                                        if A8:A[I]=W
                                        if X and not j:A[I]=-abs(W)
                                        if X and j:A[I]=W
                                        if g!=0:A[I]=g
                                else:LOGGER.error('国家电网账户余额获取失败！')
                                if I not in A:A[I]=0
                                await C.__get_door_daily_bill(A,H.year,V,U)
                                if _i not in A:LOGGER.error('国家电网无法获取日用电数据！');continue
                                Y=0;K=_N
                                for k in range(10):
                                        E=A[_i][k]
                                        try:float(E[_t]);K=_V;break
                                        except:Y=Y+1
                                l=0;m=0;n=0;o=0;p=0;A[z]=f"{H.year}-{H.month:02d}-{H.day:02d}"
                                if K:
                                        for k in range(Y):A[_i].pop(0)
                                        E=A[_i][0];G=datetime.datetime.strptime(E[R],A0);A[z]=f"{G.year}-{G.month:02d}-{G.day:02d}";l=catchFloat(E,_t);m=catchFloat(E,_z);n=catchFloat(E,_A0);o=catchFloat(E,_A1);p=catchFloat(E,_A2)
                                A['daily_ele_num']=normal_round(l,2);A['daily_p_ele_num']=normal_round(m,2);A['daily_v_ele_num']=normal_round(n,2);A['daily_n_ele_num']=normal_round(o,2);A['daily_t_ele_num']=normal_round(p,2);q=0;r=0;s=0;t=0;u=0
                                if K:
                                        for B in A[_i]:
                                                A9=datetime.datetime.strptime(B[R],A0)
                                                if A9.month!=G.month:break
                                                q+=catchFloat(B,_t);r+=catchFloat(B,_z);s+=catchFloat(B,_A0);t+=catchFloat(B,_A1);u+=catchFloat(B,_A2)
                                A[_AD]=normal_round(q,2);A[_A3]=normal_round(r,2);A[_A4]=normal_round(s,2);A[_A5]=normal_round(t,2);A[_A6]=normal_round(u,2)
                                if K:
                                        Z=G-datetime.timedelta(days=G.day)
                                        if _S not in A or len(A[_S])<12:await C.__get_door_bill(A,Z.year-1)
                                        v=await C.__get_door_bill(A,Z.year)
                                        if v is not _D:A[S]=v
                                        w=[]
                                        if _S in A:
                                                for B in A[_S]:
                                                        if _AL not in B:await C.__get_door_mouth_bill(A,B)
                                                        if _Au not in B:AA,F,D=get_month_date_range(B[_Z]);U=f"{D.year}-{D.month:02d}-{D.day:02d}";V=f"{F.year}-{F.month:02d}-{F.day:02d}";await C.__get_door_daily_bill(A,int(AA),V,U,B)
                                                        if B[_Z].startswith(str(Z.year)):w.append(B)
                                        A[J]=sorted(w,key=lambda x:x[_Z],reverse=_V)
                                if S in A:A[T]=catchFloat(A[S],'totalEleNum');A[A1]=catchFloat(A[S],'totalEleCost')
                                if T not in A:A[T]=0;A[A1]=0
                                x=0;a=D
                                if J in A and len(A[J])>0:
                                        L=A[J][0];A[d]=catchFloat(L,e);A[A2]=catchFloat(L,A3)
                                        if _AL in L:x=L[_AL][_At]
                                        a=datetime.datetime.strptime(L[_Z],'%Y%m')
                                if d not in A:A[d]=0;A[A2]=0
                                A['last_month_meter_num']=int(x);M=0;N=0;O=0;P=0;Q=0
                                if a.month==12:M=A[_AD];N=A[_A3];O=A[_A4];P=A[_A5];Q=A[_A6]
                                else:
                                        if J in A:
                                                for B in A[J]:M+=catchFloat(B,e);N+=B[_A3];O+=B[_A4];P+=B[_A5];Q+=B[_A6]
                                        if K and G.month!=a.month:M+=A[_AD];N+=A[_A3];O+=A[_A4];P+=A[_A5];Q+=A[_A6]
                                A[T]=normal_round(M,2);A['year_p_ele_num']=normal_round(N,2);A['year_v_ele_num']=normal_round(O,2);A['year_n_ele_num']=normal_round(P,2);A['year_t_ele_num']=normal_round(Q,2)
                                if _i in A:
                                        b=[]
                                        for B in A[_i][:30]:b.append({R:B[R],'ele':normal_round(catchFloat(B,_t),2),'v_ele':normal_round(catchFloat(B,_A0),2),'p_ele':normal_round(catchFloat(B,_z),2),'n_ele':normal_round(catchFloat(B,_A1),2),'t_ele':normal_round(catchFloat(B,_A2),2)})
                                        b.reverse();A[A4]=b
                                else:A[A4]=[]
                                if _S in A:
                                        A[_S]=sorted(A[_S],key=lambda x:x[_Z],reverse=_V);c=[]
                                        for B in A[_S][:12]:c.append({_Z:B[_Z],'cost':normal_round(catchFloat(B,A3),2),'ele':normal_round(catchFloat(B,e),2),'v_ele':B[_A4],'p_ele':B[_A3],'n_ele':B[_A5],'t_ele':B[_A6]})
                                        c.reverse();A[A5]=c
                                else:A[A5]=[]
                                A['refresh_time']=datetime.datetime.strftime(H,'%Y-%m-%d %H:%M:%S')
                        await C.save_data()
                except:return 0

        def get_door_account_list(A):return list(A.doorAccountDict.values())
        def get_door_account(A):return A.doorAccountDict
