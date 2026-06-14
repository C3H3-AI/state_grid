import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.selector import selector
from .const import DOMAIN, LLM_BASE_URL, LLM_MODEL
from .utils.logger import LOGGER
from .data_client import StateGridDataClient
from . import click_captcha_solver


class StateGridOnnxConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """国家电网集成的配置向导（手机号+邮箱降级登录）。"""

    VERSION = 12

    async def async_step_user(self, user_input=None):
        """配置步骤：输入手机号、邮箱（备用）、密码和 LLM 配置。"""
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        if self.hass.data.get(DOMAIN):
            return self.async_abort(reason="single_instance_allowed")

        errors: dict[str, str] = {}
        phone: str = ""
        email: str = ""
        password: str = ""
        llm_api_key: str = ""
        llm_base_url: str = LLM_BASE_URL
        llm_model: str = LLM_MODEL

        if user_input is not None:
            phone = user_input.get("phone", "").strip()
            email = user_input.get("email", "").strip()
            password = user_input.get("password", "")
            llm_api_key = user_input.get("llm_api_key", "").strip()
            llm_base_url = user_input.get("llm_base_url", LLM_BASE_URL).strip()
            llm_model = user_input.get("llm_model", LLM_MODEL).strip()

            if not phone or not password:
                errors["base"] = "invalid_auth"
            elif not phone.isdigit():
                errors["base"] = "invalid_phone"
            elif email and "@" not in email:
                errors["base"] = "invalid_email"
            elif not llm_api_key:
                errors["base"] = "missing_llm_key"

            if not errors:
                dc = StateGridDataClient(hass=self.hass, config=None)
                dc.llm_api_key = llm_api_key
                dc.llm_base_url = llm_base_url
                dc.llm_model = llm_model
                dc.email_account = email

                click_captcha_solver.configure_llm(llm_api_key, llm_base_url, llm_model)

                try:
                    LOGGER.debug(
                        "开始登录国家电网，手机号=%s，备用邮箱=%s，LLM模型=%s",
                        phone, email or "未配置", llm_model,
                    )
                    result = await dc.password_login(phone, password, encode=False, retry=3)
                except Exception as exc:
                    LOGGER.error("国家电网登录异常: %s", exc)
                    errors["base"] = "cannot_connect"
                else:
                    if result.get("errcode") == 0:
                        try:
                            await dc.save_data()
                        except Exception:
                            LOGGER.exception("保存 state_grid.config 失败，但登录成功。")
                        self.hass.data[DOMAIN] = dc
                        title = f"国家电网 - {phone}"
                        return self.async_create_entry(
                            title=title,
                            data={
                                "llm_api_key": llm_api_key,
                                "llm_base_url": llm_base_url,
                                "llm_model": llm_model,
                                "email_account": email,
                            },
                        )
                    else:
                        errmsg = (
                            result.get("errmsg")
                            or result.get("message")
                            or "登录失败，请检查账号密码或LLM配置"
                        )
                        LOGGER.warning("国家电网登录失败: %s", errmsg)
                        if "RK001" in errmsg or "流控" in errmsg or "日额度" in errmsg:
                            errors["base"] = "rk001_rate_limit"
                        else:
                            errors["base"] = "invalid_auth"

        data_schema = vol.Schema(
            {
                vol.Required("phone", default=phone): selector(
                    {"text": {"type": "text"}}
                ),
                vol.Optional("email", default=email): selector(
                    {"text": {"type": "text"}}
                ),
                vol.Required("password", default=password): selector(
                    {"text": {"type": "password"}}
                ),
                vol.Required("llm_api_key", default=llm_api_key): selector(
                    {"text": {"type": "password"}}
                ),
                vol.Optional("llm_base_url", default=llm_base_url): selector(
                    {"text": {"type": "text"}}
                ),
                vol.Optional("llm_model", default=llm_model): selector(
                    {"text": {"type": "text"}}
                ),
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "fallback_hint": "手机号登录遇RK001流控时，将自动降级为邮箱登录（需填写备用邮箱）"
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(entry: config_entries.ConfigEntry):
        """返回选项流程。"""
        return OptionsFlowHandler(entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """集成选项：可以修改 LLM 配置和刷新间隔。"""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """选项配置入口。"""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        data_schema = vol.Schema(
            {
                vol.Optional("llm_api_key"): selector({"text": {"type": "password"}}),
                vol.Optional("llm_base_url"): selector({"text": {"type": "text"}}),
                vol.Optional("llm_model"): selector({"text": {"type": "text"}}),
            }
        )
        return self.async_show_form(step_id="init", data_schema=data_schema)
