DOMAIN = "state_grid"
PACKAGE_NAME = "custom_components.state_grid"
VERSION = "0.4.0"
VERSION_STORAGE = 11
STORAGE_KEY = "state_grid.config"

# 流控相关错误码（手机号登录遇限流时，自动降级为邮箱登录）
# 11401 = RK001 限流（"网络连接超时（RK001）,请重试！"）
# 注意：10015/30010/10002 不是流控码，是 token 失效/需重新登录的错误码
FLOW_CONTROL_CODES = {11401}

# LLM 验证码识别配置
LLM_API_KEY = ""
LLM_BASE_URL = "https://ark.cn-beijing.volces.com/api/v3"
LLM_MODEL = "doubao-seed-2-0-pro-260215"
