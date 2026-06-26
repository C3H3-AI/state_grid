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
        self._saved_basic = {}  # basic settings from step_init
        self._selected_accounts = []  # accounts selected in step_pricing_select
        self._pricing_config = {}  # per-account pricing config

    # ── Step 1: Basic settings (LLM, refresh interval) ──
    async def async_step_init(self, user_input=None):
        current = {**(self._entry.data or {}), **(self._entry.options or {})}
        existing_pricing = current.get("pricing", {})

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

            # Update running data_client
            dc = self.hass.data.get(DOMAIN)
            if dc:
                for k in ("llm_api_key", "llm_base_url", "llm_model", "email_account", "refresh_interval"):
                    if k in new_data:
                        setattr(dc, k, new_data[k])
                if dc.llm_api_key:
                    click_captcha_solver.configure_llm(dc.llm_api_key, dc.llm_base_url, dc.llm_model)

            self._saved_basic = new_data
            self._pricing_config = existing_pricing
            return await self.async_step_pricing_select()

        def _str(key, fb=""):
            v = current.get(key)
            return fb if v is None else str(v)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Optional("llm_api_key", default=""): selector({"text": {"type": "password"}}),
                vol.Optional("llm_base_url", default=_str("llm_base_url", LLM_BASE_URL)): selector({"text": {"type": "text"}}),
                vol.Optional("llm_model", default=_str("llm_model", LLM_MODEL)): selector({"text": {"type": "text"}}),
                vol.Optional("email_account", default=_str("email_account", "")): selector({"text": {"type": "text"}}),
                vol.Optional("refresh_interval", default=_str("refresh_interval", "12"),
                             description="刷新间隔（小时，1-48）"): selector({"text": {"type": "text"}}),
            }),
        )

    # ── Step 2: Select accounts for pricing config ──
    async def async_step_pricing_select(self, user_input=None):
        dc = self.hass.data.get(DOMAIN)
        accounts = {}
        if dc and dc.doorAccountDict:
            accounts = {
                acc_id: acc.get("consName_dst", acc_id)
                for acc_id, acc in dc.doorAccountDict.items()
            }
        if not accounts:
            # No accounts yet — save and exit
            return self.async_create_entry(title="", data={**self._saved_basic, "pricing": self._pricing_config})

        acc_options = [("%s (%s)" % (acc_id, name)) for acc_id, name in accounts.items()]

        if user_input is not None:
            selected = user_input.get("accounts", [])
            self._selected_accounts = [s.split(" ")[0] for s in selected]
            if self._selected_accounts:
                return await self.async_step_pricing_config()
            # No accounts selected — skip pricing
            return self.async_create_entry(title="", data={**self._saved_basic, "pricing": self._pricing_config})

        # Default: select all accounts that already have pricing config
        default_selection = [("%s (%s)" % (aid, accounts[aid])) for aid in self._pricing_config]

        return self.async_show_form(
            step_id="pricing_select",
            data_schema=vol.Schema({
                vol.Optional("accounts", default=default_selection): selector({
                    "select": {
                        "options": acc_options,
                        "multiple": True,
                        "custom_value": False,
                    }
                }),
            }),
            description_placeholders={"hint": "选择要配置电价的账户，不选则跳过"},
        )

    # ── Step 3: Pricing config for selected accounts ──
    async def async_step_pricing_config(self, user_input=None):
        if user_input is not None:
            # Save pricing for each selected account
            acc_ids = self._selected_accounts
            for acc_id in acc_ids:
                cfg = {}
                for f in PRICING_FIELDS:
                    val = user_input.get(f)
                    if val is not None and val != "":
                        if f == CONF_BILLING_STANDARD:
                            cfg[f] = str(val)
                        elif f == CONF_FAMILY_MEMBERS:
                            try:
                                cfg[f] = int(val)
                            except (ValueError, TypeError):
                                cfg[f] = 0
                        else:
                            try:
                                cfg[f] = float(val)
                            except (ValueError, TypeError):
                                pass
                if cfg:
                    self._pricing_config[acc_id] = cfg

            # Update running data_client
            dc = self.hass.data.get(DOMAIN)
            if dc:
                # Merge with existing pricing config
                merged = dc.pricing_config if hasattr(dc, "pricing_config") else {}
                merged.update(self._pricing_config)
                for acc_id in acc_ids:
                    if acc_id in self._pricing_config:
                        merged[acc_id] = self._pricing_config[acc_id]
                dc.pricing_config = self._pricing_config

            return self.async_create_entry(title="", data={**self._saved_basic, "pricing": self._pricing_config})

        # Build form for the first selected account (all accounts share same form)
        acc_id = self._selected_accounts[0] if self._selected_accounts else ""
        existing = self._pricing_config.get(acc_id, {})

        def _pv(key, fb=""):
            v = existing.get(key)
            return fb if v is None else str(v)

        return self.async_show_form(
            step_id="pricing_config",
            data_schema=vol.Schema({
                vol.Optional(CONF_BILLING_STANDARD, default=_pv(CONF_BILLING_STANDARD, BILLING_YEAR_LADDER),
                             description="计费方式"): selector({
                    "select": {"options": ["year_ladder", "year_ladder_fpg", "average"]}
                }),
                vol.Optional(CONF_FAMILY_MEMBERS, default=_pv(CONF_FAMILY_MEMBERS, "0"),
                             description="一户多人人数（0=不启用）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_LEVEL_1, default=_pv(CONF_LADDER_LEVEL_1, str(DEFAULT_LADDER_LEVEL_1)),
                             description="一档上限（kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_LEVEL_2, default=_pv(CONF_LADDER_LEVEL_2, str(DEFAULT_LADDER_LEVEL_2)),
                             description="二档上限（kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_PRICE_1, default=_pv(CONF_LADDER_PRICE_1, str(DEFAULT_LADDER_PRICE_1)),
                             description="一档电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_PRICE_2, default=_pv(CONF_LADDER_PRICE_2, str(DEFAULT_LADDER_PRICE_2)),
                             description="二档电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_LADDER_PRICE_3, default=_pv(CONF_LADDER_PRICE_3, str(DEFAULT_LADDER_PRICE_3)),
                             description="三档电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_PRICE_PEAK, default=_pv(CONF_PRICE_PEAK, str(DEFAULT_PRICE_PEAK)),
                             description="峰电电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_PRICE_VALLEY, default=_pv(CONF_PRICE_VALLEY, str(DEFAULT_PRICE_VALLEY)),
                             description="谷电电价（元/kWh）"): selector({"text": {"type": "text"}}),
                vol.Optional(CONF_AVERAGE_PRICE, default=_pv(CONF_AVERAGE_PRICE, str(DEFAULT_AVERAGE_PRICE)),
                             description="平均单价（元/kWh）"): selector({"text": {"type": "text"}}),
            }),
            description_placeholders={"accounts": ", ".join(self._selected_accounts[:5])},
        )
