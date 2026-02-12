from __future__ import annotations

from datetime import datetime
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
    children: List[Union[Group, Condition]]


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


class AttachmentModel(BaseModel):
    DownloadUrl: Optional[str] = Field(default=None, description="文件的下载地址")
    WaterMarkInfo: Optional[Any] = Field(default=None, description="文件水印信息")
    allow_down: Optional[bool] = Field(default=None, description="是否允许下载")
    allow_edit: Optional[bool] = Field(default=None, description="是否允许编辑")
    allow_view: Optional[bool] = Field(default=None, description="是否允许预览")
    createTime: Optional[Union[datetime, str]] = Field(default=None, description="文件创建时间")
    duration: Optional[float] = Field(default=None, description="音视频文件的时长（秒）")
    file_id: Optional[str] = Field(default=None, description="文件的唯一ID")
    file_name: Optional[str] = Field(default=None, description="文件名")
    file_path: Optional[str] = Field(default=None, description="文件在服务器上的存储路径")
    file_size: Optional[int] = Field(default=None, description="文件大小（字节）")
    file_type: Optional[int] = Field(default=None, description="文件类型的一种数字表示")
    height: Optional[int] = Field(default=None, description="图片或视频的高度（像素）")
    is_delete: Optional[bool] = Field(default=None, description="文件是否已被删除")
    is_knowledge: Optional[bool] = Field(default=None, description="是否为知识库文件")
    large_thumbnail_name: Optional[str] = Field(default=None, description="大缩略图名称")
    large_thumbnail_path: Optional[str] = Field(default=None, description="大缩略图路径")
    node_id: Optional[str] = Field(default="", description="关联的节点ID")
    origin_link_url: Optional[str] = Field(default=None, description="原始链接URL")
    original_file_full_path: Optional[str] = Field(default=None, description="原始文件的完整路径")
    original_file_name: Optional[str] = Field(default=None, description="原始文件名")
    preview_url: Optional[str] = Field(default=None, description="文件的预览地址")
    share_folder_url: Optional[str] = Field(default=None, description="共享文件夹地址")
    short_link_url: Optional[str] = Field(default=None, description="短链接地址")
    thumbnail_name: Optional[str] = Field(default="", description="缩略图名称")
    thumbnail_path: Optional[str] = Field(default="", description="缩略图路径")
    width: Optional[int] = Field(default=None, description="图片或视频的宽度（像素）")


class AttachmentCreateModel(BaseModel):
    name: Optional[str] = Field(default=None, description="文件名")
    url: Optional[str] = Field(default=None, description="文件base64格式的值(不是url)")


class AccountModel(BaseModel):
    accountId: Optional[str] = Field(default=None, description="用户的唯一标识ID")
    avatar: Optional[str] = Field(default=None, description="用户头像的URL")
    email: Optional[str] = Field(default=None, description="用户的电子邮件地址")
    fullname: Optional[str] = Field(default=None, description="用户的全名")
    jobNumber: Optional[str] = Field(default=None, description="用户的工号")
    mobilePhone: Optional[str] = Field(default=None, description="用户的手机号码")
    status: Optional[int] = Field(default=None, description="用户状态, 例如: 1表示正常")
