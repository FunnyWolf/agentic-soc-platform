from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Annotated, Union, ClassVar, Optional

from pydantic import BeforeValidator, PlainSerializer, BaseModel, ConfigDict, Field, field_validator


class AccountModel(BaseModel):
    accountId: Optional[str] = Field(default=None, description="User's unique identifier ID (用户的唯一标识ID)")
    avatar: Optional[str] = Field(default=None, description="User avatar URL (用户头像的URL)")
    email: Optional[str] = Field(default=None, description="User email address (用户的电子邮件地址)")
    fullname: Optional[str] = Field(default=None, description="User full name (用户的全名)")
    jobNumber: Optional[str] = Field(default=None, description="User job number (用户的工号)")
    mobilePhone: Optional[str] = Field(default=None, description="User mobile phone number (用户的手机号码)")
    status: Optional[int] = Field(default=None, description="User status, e.g., 1 means active (用户状态, 例如: 1表示正常)")


def validate_datetime(v: Any) -> Any:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    if not isinstance(v, str):
        return v

    value = v.strip()
    if not value:
        return None

    local_tz = datetime.now().astimezone().tzinfo or timezone.utc

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=local_tz)
        return dt
    except ValueError:
        pass

    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=local_tz)
    except ValueError:
        raise ValueError(f"Unsupported datetime format: {value}")


def serialize_datetime(v: Any) -> Any:
    if isinstance(v, datetime):
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        dt = v.replace(tzinfo=local_tz) if v.tzinfo is None else v
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return v


AutoDatetime = Annotated[
    Union[datetime, None],
    BeforeValidator(validate_datetime),
    PlainSerializer(serialize_datetime)
]


def validate_account(v: Any) -> Any:
    if not v:
        return ""
    if isinstance(v, dict):
        return v.get("fullname")
    if isinstance(v, list):
        if len(v) == 0:
            return ""
        elif len(v) == 1:
            if isinstance(v[0], str):
                return v[0]
            elif isinstance(v[0], dict):
                return v[0].get("fullname")
            else:
                raise ValueError(f"Unsupported account format: {v}")
        else:
            tmp = []
            for one in v:
                if isinstance(one, str):
                    tmp.append(one)
                elif isinstance(one, dict):
                    tmp.append(one.get("fullname"))
                else:
                    raise ValueError(f"Unsupported account format: {one}")
            return tmp

    if not isinstance(v, str):
        return v
    raise ValueError(f"Unsupported account format: {v}")


AutoAccount = Annotated[
    str,
    BeforeValidator(validate_account),
]


class BaseSystemModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    _AI_EXCLUDE_FIELDS: ClassVar[set[str]] = {"row_owner", "row_createdBy", "row_updatedBy"}  # 不传递给 AI 的字段

    row_id: Optional[str] = Field(default=None, description="Unique row ID (唯一行 ID)")
    row_owner: Optional[AutoAccount] = Field(default=None, description="Record owner (记录所有者)")
    row_createdBy: Optional[AutoAccount] = Field(default=None, description="Creator (创建者)")
    row_createdAt: Optional[AutoDatetime] = Field(alias="create_time", default=None, description="Record created time (记录创建时间)")
    row_updatedAt: Optional[AutoDatetime] = Field(alias="update_time", default=None, description="Record last updated time (记录最后更新时间)")
    row_updatedBy: Optional[AutoAccount] = Field(default=None, description="Last updated by (最后更新人)")

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # 将当前类的集合与父类的集合自动合并
        cls._AI_EXCLUDE_FIELDS = cls._AI_EXCLUDE_FIELDS | BaseSystemModel._AI_EXCLUDE_FIELDS

    @field_validator("row_owner", mode="before")
    @classmethod
    def empty_list_to_none(cls, v: Any) -> Any:
        if isinstance(v, list) and len(v) == 0:
            return None
        return v

    def model_dump_for_ai(
            self,
            *,
            exclude_none: bool = True,
            exclude_unset: bool = True,
            exclude_default: bool = True,
    ) -> dict[str, Any]:
        return self.model_dump(
            exclude=self._AI_EXCLUDE_FIELDS,
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_default,
            by_alias=True
        )

    def model_dump_json_for_ai(
            self,
            *,
            exclude_none: bool = True,
            exclude_unset: bool = True,
            exclude_default: bool = True,
    ) -> str:
        return self.model_dump_json(
            exclude=self._AI_EXCLUDE_FIELDS,
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_default,
            by_alias=True
        )
