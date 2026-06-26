"""Config flow for State Grid integration with multi-account pricing."""

from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.selector import selector
from .const import DOMAIN, LLM_BASE_URL, LLM_MODEL
from .const import (
    BILLING_YEAR_LADDER, BILLING_YEAR_LADDER_FPG, BILLING_AVERAGE,
    CONF_BILLING_STANDARD, CONF_LADDER_LEVEL_1, CONF_LADDER_LEVEL_2,
    CONF_LADDER_PRICE_1, CONF_LADDER_PRICE_2, CONF_LADDER_PRICE_3,
    CONF_PRICE_PEAK, CONF_PRICE_VALLEY, CONF_AVERAGE_PRICE, CONF_FAMILY_MEMBERS,
    DEFAULT_LADDER_LEVEL_1, DEFAULT_LADDER_LEVEL_2,
    DEFAULT_LADDER_PRICE_1, DEFAULT_LADDER_PRICE_2, DEFAULT_LADDER_PRICE_3,
    DEFAULT_PRICE_PEAK, DEFAULT_PRICE_VALLEY, DEFAULT_AVERAGE_PRICE, DEFAULT_FAMILY_MEMBERS,
)
from .utils.logger import LOGGER
from .data_client import StateGridDataClient
from . import click_captcha_solver

PRICING_FIELDS = [
    CONF_BILLING_STANDARD, CONF_FAMILY_MEMBERS,
    CONF_LADDER_LEVEL_1, CONF_LADDER_LEVEL_2,
    CONF_LADDER_PRICE_1, CONF_LADDER_PRICE_2, CONF_LADDER_PRICE_3,
    CONF_PRICE_PEAK, CONF_PRICE_VALLEY, CONF_AVERAGE_PRICE,
]

FAMILY_OPTIONS = [
    ("0", "不启用"), ("5", "5人"), ("7", "7人以上"),
]


class StateGridOnnxConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 12

    async def async_step_user(self, user_input=None):
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        if self.hass.data.get(DOMAIN):
            return self.async_abort(reason="single_instance_allowed")

        errors: dict[str, str] = {}
        phone = email = password = llm_api_key = ""
        llm_base_url = LLM_BASE_URL
        llm_model = LLM_MODEL

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
                    result = await dc.password_login(phone, password, encode=False, retry=3)
                    if result.get("errcode") != 0 and email and (
                        result.get("rk001") or "RK001" in (result.get("errmsg") or "")
                    ):
                        import hashlib
                        pwd_md5 = hashlib.md5(password.encode()).hexdigest().upper()
                        result = await dc._login_with_email_fallback(pwd_md5, retry=2)
                except Exception as exc:
                    LOGGER.error("登录异常: %s", exc)
                    errors["base"] = "cannot_connect"
                else:
                    if result.get("errcode") == 0:
                        try:
                            await dc.save_data()
                        except Exception:
                            LOGGER.exception("保存失败，但登录成功")
                        self.hass.data[DOMAIN] = dc
                        return self.async_create_entry(
                            title=f"国家电网 - {phone}",
                            data={"llm_api_key": llm_api_key, "llm_base_url": llm_base_url,
                                  "llm_model": llm_model, "email_account": email},
                        )
                    else:
                        errmsg = result.get("errmsg") or result.get("message") or "登录失败"
                        errors["base"] = "rk001_rate_limit" if "RK001" in errmsg else "invalid_auth"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("phone", default=phone): selector({"text": {"type": "text"}}),
                vol.Optional("email", default=email): selector({"text": {"type": "text"}}),
                vol.Required("password", default=password): selector({"text": {"type": "password"}}),
                vol.Required("llm_api_key", default=llm_api_key): selector({"text": {"type": "password"}}),
                vol.Optional("llm_base_url", default=llm_base_url): selector({"text": {"type": "text"}}),
                vol.Optional("llm_model", default=llm_model): selector({"text": {"type": "text"}}),
            }),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(entry: config_entries.ConfigEntry):
        return OptionsFlowHandler(entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry
        self._selected_account = None
        self._pricing_config = {}

    # ── Step 1: 选择修改类别 ──
    async def async_step_init(self, user_input=None):
        if user_input is not None:
            choice = user_input.get("action")
            if choice == "basic":
                return await self.async_step_basic()
            elif choice == "pricing":
                return await self.async_step_pricing_select()
            elif choice == "reauth":
                return await self.async_step_reauth()
            return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Required("action", default="basic"): selector({
                    "select": {
                        "options": [
                            ("basic", "基本设置（LLM / 刷新间隔）"),
                            ("pricing", "电价配置（各账户阶梯/单价）"),
                            ("reauth", "重新配置账号（手机号/密码）"),
                        ]
                    }
                }),
            }),
            description_placeholders={"hint": "选择要修改的配置类型"},
        )

    # ── Step 2a: 基本设置 ──
    async def async_step_basic(self, user_input=None):
        current = {**(self._entry.data or {}), **(self._entry.options or {})}
        if user_input is not None:
            new_data = {}
            for key in ("llm_api_key", "llm_base_url", "llm_model", "email_account"):
                raw_val = user_input.get(key)
                val = raw_val.strip() if isinstance(raw_val, str) else ""
                if val:
                    new_data[key] = val
                elif key in current and current[key]:
                    new_data[key] = current[key]

            refresh_val = user_input.get("refresh_interval")
            if refresh_val:
                try:
                    hours = int(str(refresh_val).strip())
                    new_data["refresh_interval"] = max(1, min(48, hours))
                except (ValueError, TypeError):
                    pass

            dc = self.hass.data.get(DOMAIN)
            if dc:
                for k in ("llm_api_key", "llm_base_url", "llm_model", "email_account", "refresh_interval"):
                    if k in new_data:
                        setattr(dc, k, new_data[k])
                if dc.llm_api_key:
                    click_captcha_solver.configure_llm(dc.llm_api_key, dc.llm_base_url, dc.llm_model)

            # Preserve existing pricing config
            existing_pricing = current.get("pricing", {})
            new_data["pricing"] = existing_pricing
            return self.async_create_entry(title="", data=new_data)

        def _str(key, fb=""):
            v = current.get(key)
            return fb if v is None else str(v)

        return self.async_show_form(
            step_id="basic",
            data_schema=vol.Schema({
                vol.Optional("llm_api_key", default=""): selector({"text": {"type": "password"}}),
                vol.Optional("llm_base_url", default=_str("llm_base_url", LLM_BASE_URL)): selector({"text": {"type": "text"}}),
                vol.Optional("llm_model", default=_str("llm_model", LLM_MODEL)): selector({"text": {"type": "text"}}),
                vol.Optional("email_account", default=_str("email_account", "")): selector({"text": {"type": "text"}}),
                vol.Optional("refresh_interval", default=_str("refresh_interval", "12"),
                             description="刷新间隔（小时，1-48）"): selector({"text": {"type": "text"}}),
            }),
        )

    # ── Step 2b: 电价配置 - 选账户 ──
    async def async_step_pricing_select(self, user_input=None):
        current = {**(self._entry.data or {}), **(self._entry.options or {})}
        self._pricing_config = dict(current.get("pricing", {}))

        dc = self.hass.data.get(DOMAIN)
        accounts = {}
        if dc and hasattr(dc, "doorAccountDict") and dc.doorAccountDict:
            accounts = {
                acc_id: acc.get("consName_dst", acc_id)
                for acc_id, acc in dc.doorAccountDict.items()
            }
        if not accounts:
            return self.async_abort(reason="no_accounts")

        acc_options = sorted(
            ["%s (%s)" % (acc_id, name) for acc_id, name in accounts.items()],
            key=lambda x: x.split("(")[1].rstrip(")")
        )

        if user_input is not None:
            selected = user_input.get("account", "")
            if selected:
                self._selected_account = selected.split(" ")[0]
                return await self.async_step_pricing_config()
            return self.async_create_entry(title="", data={**current, "pricing": self._pricing_config})

        # Default: first account that has pricing config
        default_val = ""
        for acc_id in self._pricing_config:
            label = "%s (%s)" % (acc_id, accounts.get(acc_id, ""))
            if label in acc_options:
                default_val = label
                break

        return self.async_show_form(
            step_id="pricing_select",
            data_schema=vol.Schema({
                vol.Required("account", default=default_val): selector({
                    "select": {"options": acc_options, "custom_value": False}
                }),
            }),
            description_placeholders={"hint": "选择要配置电价的账户，每个账户单独设置"},
        )

    # ── Step 3: 电价配置 - 填参数 ──
    async def async_step_pricing_config(self, user_input=None):
        current = {**(self._entry.data or {}), **(self._entry.options or {})}
        acc_id = self._selected_account

        if user_input is not None:
            cfg = {}
            # 计费方式
            cfg[CONF_BILLING_STANDARD] = user_input.get(CONF_BILLING_STANDARD, BILLING_YEAR_LADDER)
            # 一户多人（选型器）
            fm_raw = user_input.get(CONF_FAMILY_MEMBERS, "0")
            try:
                cfg[CONF_FAMILY_MEMBERS] = int(fm_raw)
            except (ValueError, TypeError):
                cfg[CONF_FAMILY_MEMBERS] = 0
            # 各档电价
            for f in [CONF_LADDER_LEVEL_1, CONF_LADDER_LEVEL_2,
                      CONF_LADDER_PRICE_1, CONF_LADDER_PRICE_2, CONF_LADDER_PRICE_3,
                      CONF_PRICE_PEAK, CONF_PRICE_VALLEY, CONF_AVERAGE_PRICE]:
                val = user_input.get(f)
                if val is not None:
                    try:
                        cfg[f] = float(val) if f != CONF_FAMILY_MEMBERS else int(val)
                    except (ValueError, TypeError):
                        pass

            self._pricing_config[acc_id] = cfg

            dc = self.hass.data.get(DOMAIN)
            if dc and hasattr(dc, "pricing_config"):
                dc.pricing_config = self._pricing_config

            return self.async_create_entry(title="", data={**current, "pricing": self._pricing_config})

        # 已有配置或默认值
        existing = self._pricing_config.get(acc_id, {})

        def _pv(key, fb=""):
            v = existing.get(key)
            return fb if v is None else str(v)

        return self.async_show_form(
            step_id="pricing_config",
            data_schema=vol.Schema({
                vol.Required(CONF_BILLING_STANDARD,
                             default=_pv(CONF_BILLING_STANDARD, BILLING_YEAR_LADDER),
                             description="计费方式"): selector({
                    "select": {"options": ["year_ladder", "year_ladder_fpg", "average"]}
                }),
                vol.Optional(CONF_FAMILY_MEMBERS,
                             default=_pv(CONF_FAMILY_MEMBERS, "0"),
                             description="一户多人"): selector({
                    "select": {
                        "options": [
                            ("0", "不启用"),
                            ("5", "5人（每档+1200度）"),
                            ("7", "7人以上（每档+2400度）"),
                        ]
                    }
                }),
                vol.Optional(CONF_LADDER_LEVEL_1,
                             default=_pv(CONF_LADDER_LEVEL_1, str(DEFAULT_LADDER_LEVEL_1)),
                             description="一档上限（kWh，一户多人自动增加）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_LEVEL_2,
                             default=_pv(CONF_LADDER_LEVEL_2, str(DEFAULT_LADDER_LEVEL_2)),
                             description="二档上限（kWh，一户多人自动增加）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_PRICE_1,
                             default=_pv(CONF_LADDER_PRICE_1, str(DEFAULT_LADDER_PRICE_1)),
                             description="一档电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_PRICE_2,
                             default=_pv(CONF_LADDER_PRICE_2, str(DEFAULT_LADDER_PRICE_2)),
                             description="二档电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_PRICE_3,
                             default=_pv(CONF_LADDER_PRICE_3, str(DEFAULT_LADDER_PRICE_3)),
                             description="三档电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_PRICE_PEAK,
                             default=_pv(CONF_PRICE_PEAK, str(DEFAULT_PRICE_PEAK)),
                             description="峰电电价（元/kWh，峰平谷时用）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_PRICE_VALLEY,
                             default=_pv(CONF_PRICE_VALLEY, str(DEFAULT_PRICE_VALLEY)),
                             description="谷电电价（元/kWh，峰平谷时用）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_AVERAGE_PRICE,
                             default=_pv(CONF_AVERAGE_PRICE, str(DEFAULT_AVERAGE_PRICE)),
                             description="平均单价（元/kWh，平均单价时用）"): selector({"text": {"type": "text"}}),
            }),
            description_placeholders={"account": acc_id},
        )

    # ── Step 2c: 重新配置账号 ──
    async def async_step_reauth(self, user_input=None):
        current = {**(self._entry.data or {}), **(self._entry.options or {})}
        errors = {}

        if user_input is not None:
            phone = user_input.get("phone", "").strip()
            password = user_input.get("password", "")

            if not phone or not password:
                errors["base"] = "invalid_auth"
            elif not phone.isdigit():
                errors["base"] = "invalid_phone"

            if not errors:
                dc = self.hass.data.get(DOMAIN)
                if dc:
                    # Update credentials and re-login
                    dc.account = phone
                    dc.password = password
                    try:
                        result = await dc.password_login(phone, password, encode=False, retry=3)
                        if result.get("errcode") == 0:
                            await dc.save_data()
                            # Preserve all existing options except auth
                            new_data = dict(current)
                            new_data["phone"] = phone
                            # Remove pricing to force fresh start
                            return self.async_create_entry(title="", data=new_data)
                        else:
                            errors["base"] = "invalid_auth"
                    except Exception as exc:
                        LOGGER.error("重新登录异常: %s", exc)
                        errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="reauth",
            data_schema=vol.Schema({
                vol.Required("phone", default=current.get("phone", "")): selector({"text": {"type": "text"}}),
                vol.Required("password", default=""): selector({"text": {"type": "password"}}),
            }),
            errors=errors,
        )
