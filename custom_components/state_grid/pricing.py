"""电价计算模块 - 支持年阶梯、年阶梯+峰平谷、平均单价"""

from __future__ import annotations
import logging

_LOGGER = logging.getLogger(__name__)

# 计费标准
BILLING_YEAR_LADDER = "year_ladder"
BILLING_YEAR_LADDER_FPG = "year_ladder_fpg"
BILLING_AVERAGE = "average"

BILLING_OPTIONS = [
    BILLING_YEAR_LADDER,
    BILLING_YEAR_LADDER_FPG,
    BILLING_AVERAGE,
]

BILLING_NAMES = {
    BILLING_YEAR_LADDER: "年阶梯计费",
    BILLING_YEAR_LADDER_FPG: "年阶梯+峰平谷",
    BILLING_AVERAGE: "平均单价",
}

# 配置键
CONF_BILLING_STANDARD = "billing_standard"
CONF_LADDER_LEVEL_1 = "ladder_level_1"
CONF_LADDER_LEVEL_2 = "ladder_level_2"
CONF_LADDER_PRICE_1 = "ladder_price_1"
CONF_LADDER_PRICE_2 = "ladder_price_2"
CONF_LADDER_PRICE_3 = "ladder_price_3"
CONF_PRICE_PEAK = "price_peak"
CONF_PRICE_VALLEY = "price_valley"
CONF_AVERAGE_PRICE = "average_price"
CONF_FAMILY_MEMBERS = "family_members"

# 浙江省居民阶梯电价默认值（一户一表）
DEFAULT_LADDER_LEVEL_1 = 2760  # 一档上限 kWh
DEFAULT_LADDER_LEVEL_2 = 4800  # 二档上限 kWh
DEFAULT_LADDER_PRICE_1 = 0.538  # 一档电价 元/kWh
DEFAULT_LADDER_PRICE_2 = 0.588  # 二档电价 元/kWh
DEFAULT_LADDER_PRICE_3 = 0.838  # 三档电价 元/kWh
DEFAULT_PRICE_PEAK = 0.568  # 峰电电价
DEFAULT_PRICE_VALLEY = 0.288  # 谷电电价
DEFAULT_AVERAGE_PRICE = 0.538  # 平均单价
DEFAULT_FAMILY_MEMBERS = 0  # 0=不启用一户多人

# 一户多人：每增加1人每月+100kWh基数
FAMILY_BASE_INCREMENT = 100  # kWh/月/人


def get_ladder_adjustment(members: int) -> int:
    """计算一户多人的阶梯基数增加量（年度）"""
    if members < 5:
        return 0
    extra_people = members - 3  # 基准3人，多出的人每人+100/月
    return extra_people * FAMILY_BASE_INCREMENT * 12


def calculate_daily_cost(
    day_ele: float,
    day_p_ele: float,
    day_v_ele: float,
    year_accumulated: float,
    config: dict,
) -> float:
    """计算每日电费

    Args:
        day_ele: 当日总用电量 (kWh)
        day_p_ele: 当日峰电用电量 (kWh)
        day_v_ele: 当日谷电用电量 (kWh)
        year_accumulated: 截止当日的年累计用电量 (kWh)
        config: 电价配置字典

    Returns:
        当日电费 (元)
    """
    standard = config.get(CONF_BILLING_STANDARD, BILLING_YEAR_LADDER)

    if standard == BILLING_AVERAGE:
        avg_price = config.get(CONF_AVERAGE_PRICE, DEFAULT_AVERAGE_PRICE)
        return round(day_ele * avg_price, 2)

    # 计算阶梯基数
    members = config.get(CONF_FAMILY_MEMBERS, DEFAULT_FAMILY_MEMBERS)
    adjustment = get_ladder_adjustment(members)

    level_1 = config.get(CONF_LADDER_LEVEL_1, DEFAULT_LADDER_LEVEL_1) + adjustment
    level_2 = config.get(CONF_LADDER_LEVEL_2, DEFAULT_LADDER_LEVEL_2) + adjustment

    price_1 = config.get(CONF_LADDER_PRICE_1, DEFAULT_LADDER_PRICE_1)
    price_2 = config.get(CONF_LADDER_PRICE_2, DEFAULT_LADDER_PRICE_2)
    price_3 = config.get(CONF_LADDER_PRICE_3, DEFAULT_LADDER_PRICE_3)

    if standard == BILLING_YEAR_LADDER_FPG:
        price_peak = config.get(CONF_PRICE_PEAK, DEFAULT_PRICE_PEAK)
        price_valley = config.get(CONF_PRICE_VALLEY, DEFAULT_PRICE_VALLEY)
        # 峰谷分开计费
        cost_peak = _calc_ladder_cost(day_p_ele, year_accumulated, level_1, level_2, price_1, price_2, price_3)
        # 谷电单独计费（使用峰电的年累计来判断阶梯当量）
        cost_valley = _calc_ladder_cost(day_v_ele, year_accumulated, level_1, level_2, price_valley, price_valley, price_valley)
        return round(cost_peak + cost_valley, 2)

    # 年阶梯计费（不分时）
    return round(_calc_ladder_cost(day_ele, year_accumulated, level_1, level_2, price_1, price_2, price_3), 2)


def _calc_ladder_cost(
    day_ele: float,
    year_accumulated: float,
    level_1: float,
    level_2: float,
    price_1: float,
    price_2: float,
    price_3: float,
) -> float:
    """年阶梯电费计算（含跨阶梯拆分）"""
    before_ele = year_accumulated - day_ele  # 当日之前的累计用电

    if before_ele >= level_2:
        # 完全在第三档
        cost = day_ele * price_3
    elif before_ele >= level_1:
        # 跨二、三档或完全在第二档
        second_remain = level_2 - before_ele
        if second_remain >= day_ele:
            cost = day_ele * price_2
        else:
            cost = second_remain * price_2 + (day_ele - second_remain) * price_3
    else:
        # 跨一、二档或完全在一档
        first_remain = level_1 - before_ele
        if first_remain >= day_ele:
            cost = day_ele * price_1
        else:
            second_part = min(day_ele - first_remain, level_2 - level_1)
            third_part = day_ele - first_remain - second_part
            cost = first_remain * price_1 + second_part * price_2 + third_part * price_3

    return cost
