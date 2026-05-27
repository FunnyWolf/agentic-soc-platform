from __future__ import annotations

from enum import Enum
from typing import Optional, Any, Union, TypedDict, Literal, List

from pydantic import BaseModel, Field


class FieldType(TypedDict):
    id: str
    name: str
    alias: str
    type: str
    subType: str
    desc: str
    isTitle: bool
    max: int
    options: list
    precision: str
    unit: str
    remark: str
    value: str
    required: bool
    dataSource: str
    sourceField: str

    isHidden: bool
    isReadOnly: bool
    isHiddenOnCreate: bool
    isUnique: bool


class OptionType(TypedDict):
    key: str
    value: str
    index: int
    score: float


class Condition(BaseModel):
    type: Literal["condition"] = "condition"
    field: str
    operator: Operator = Field(..., description="运算符列表")
    value: Optional[Any] = None


class Group(BaseModel):
    type: Literal["group"] = "group"
    logic: Literal["AND", "OR"] = "AND"
    children: List[Union[Group, Condition]] = []


class Operator(str, Enum):
    """查询运算符枚举"""
    EQ = "eq"  # 等于 "Beijing" 或 ["<targetid>"]
    NE = "ne"  # 不等于 "London" 或 ["<targetid>"]
    GT = "gt"  # 大于 20 或 "2025-02-06 00:00:00"
    GE = "ge"  # 大于等于 10
    LT = "lt"  # 小于 20
    LE = "le"  # 小于等于 100
    IN = "in"  # 是其中一个 ["value1", "value2"]
    # NOT_IN = "notin"  # 不是任意一个 ["value1", "value2"] # TODO BUG
    CONTAINS = "contains"  # 包含 "Ch" 或 ["销售部", "市场部"]
    NOT_CONTAINS = "notcontains"  # 不包含 "Ch" 或 ["销售部", "市场部"]
    CONCURRENT = "concurrent"  # 同时包含 ["<id1>", "<id2>"]
    BELONGS_TO = "belongsto"  # 属于 ["<departmentid>"]
    NOT_BELONGS_TO = "notbelongsto"  # 不属于 ["<departmentid>"]
    STARTS_WITH = "startswith"  # 开头是 "张"
    NOT_STARTS_WITH = "notstartswith"  # 开头不是 "李"
    ENDS_WITH = "endswith"  # 结尾是 "公司"
    NOT_ENDS_WITH = "notendswith"  # 结尾不是 "有限公司"
    BETWEEN = "between"  # 在范围内 ["2025-01-01", "2025-01-31"]
    NOT_BETWEEN = "notbetween"  # 不在范围内 ["10", "20"]
    IS_EMPTY = "isempty"  # 为空 (不需要 value)
    IS_NOT_EMPTY = "isnotempty"  # 不为空 (不需要 value)
