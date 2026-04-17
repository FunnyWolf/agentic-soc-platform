from abc import ABC
from typing import TypeVar, Generic, Type, List, Dict, Union, Any

from pydantic import BaseModel

from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.nocolymodel import Condition, Group, Operator
from PLUGINS.SIRP.sirpmodel import BaseSystemModel


def model_to_fields(model_instance: BaseModel) -> List[Dict[str, Any]]:
    fields = []
    model_data = model_instance.model_dump(mode='json', exclude_unset=True)
    for key, value in model_data.items():
        field_info = model_instance.model_fields.get(key)
        field_item = {
            'id': key,
            'value': value
        }
        if field_info and field_info.json_schema_extra:
            field_item.update(field_info.json_schema_extra)
        fields.append(field_item)
    return fields


# 定义泛型类型
T = TypeVar('T', bound=BaseSystemModel)


class BaseWorksheetEntity(ABC, Generic[T]):
    """通用工作表实体基类 - 支持泛型和关联加载"""

    WORKSHEET_ID: str
    MODEL_CLASS: Type[T]

    @classmethod
    def get(
            cls,
            row_id: str,
            include_system_fields: bool = True,
            lazy_load: bool = False
    ) -> T:
        """获取单条记录

        Args:
            row_id: 记录ID
            include_system_fields: 是否包含系统字段
            lazy_load: 是否延迟加载关联数据（True时不加载关联）

        Returns:
            模型实例
        """
        result = WorksheetRow.get(
            cls.WORKSHEET_ID,
            row_id,
            include_system_fields=include_system_fields
        )
        model = cls.MODEL_CLASS(**result)

        if not lazy_load:
            model = cls._load_relations(model, include_system_fields)

        return model

    @classmethod
    def list(
            cls,
            filter_model: Group,
            include_system_fields: bool = True,
            lazy_load: bool = False
    ) -> List[T]:
        """按过滤条件列表查询

        Args:
            filter_model: 过滤条件Group对象
            include_system_fields: 是否包含系统字段
            lazy_load: 是否延迟加载关联数据（True时不加载关联）

        Returns:
            模型实例列表
        """
        if filter_model.children:
            filter_dict = filter_model.model_dump()
        else:
            filter_dict = {}
        result = WorksheetRow.list(
            cls.WORKSHEET_ID,
            filter_dict,
            include_system_fields=include_system_fields
        )

        model_list = []
        for item in result:
            model_obj = cls.MODEL_CLASS(**item)
            if not lazy_load:
                model_obj = cls._load_relations(model_obj, include_system_fields)
            model_list.append(model_obj)

        return model_list

    @classmethod
    def update_by_filter(cls,
                         filter_model: Group,
                         model: T,
                         include_system_fields: bool = True) -> dict:
        filter_dict = filter_model.model_dump()
        result = WorksheetRow.list(
            cls.WORKSHEET_ID,
            filter_dict,
            fields=["row_id"],
            include_system_fields=include_system_fields
        )
        row_ids = []
        for item in result:
            row_ids.append(item["row_id"])

        model = cls._prepare_for_save(model)

        fields = model_to_fields(model)
        result = WorksheetRow.batch_update(cls.WORKSHEET_ID, row_ids, fields)
        return result

    @classmethod
    def list_by_row_ids(
            cls,
            row_ids: List[Any],
            include_system_fields: bool = True,
            lazy_load: bool = False
    ) -> Union[List[T], List[str], None]:
        """按ID列表查询

        Args:
            row_ids: 记录ID列表
            include_system_fields: 是否包含系统字段
            lazy_load: 是否延迟加载关联数据

        Returns:
            模型实例列表或原始row_ids列表
        """

        if row_ids is not None and row_ids != []:
            if isinstance(row_ids[0], BaseSystemModel):
                return row_ids

            filter_model = Group(
                logic="AND",
                children=[
                    Condition(
                        field="row_id",
                        operator=Operator.IN,
                        value=row_ids
                    )
                ]
            )
            return cls.list(filter_model, include_system_fields=include_system_fields, lazy_load=lazy_load)
        return row_ids

    @classmethod
    def create(cls, model: T) -> str:
        """创建记录

        Args:
            model: 模型实例

        Returns:
            新创建的记录ID
        """
        model = cls._prepare_for_save(model)

        fields = model_to_fields(model)
        row_id = WorksheetRow.create(cls.WORKSHEET_ID, fields)
        return row_id

    @classmethod
    def update(cls, model: T) -> str:
        """更新记录

        Args:
            model: 模型实例（必须包含row_id）

        Returns:
            更新的记录ID

        Raises:
            ValueError: 当row_id为None时
        """
        if model.row_id is None:
            raise ValueError(f"{cls.__name__} row_id is None, cannot update.")

        model = cls._prepare_for_save(model)

        fields = model_to_fields(model)
        row_id = WorksheetRow.update(cls.WORKSHEET_ID, model.row_id, fields)
        return row_id

    @classmethod
    def update_or_create(cls, model: T) -> str:
        """更新或创建记录

        Args:
            model: 模型实例

        Returns:
            记录ID
        """
        model = cls._prepare_for_save(model)

        fields = model_to_fields(model)

        if model.row_id is None:
            row_id = WorksheetRow.create(cls.WORKSHEET_ID, fields)
        else:
            row_id = WorksheetRow.update(cls.WORKSHEET_ID, model.row_id, fields)

        return row_id

    @classmethod
    def batch_update_or_create(cls, model_list: List[Union[T, str]]) -> Union[List[str], None]:
        """批量更新

        Args:
            model_list: 模型实例或ID字符串的列表

        Returns:
            更新后的记录ID列表

        Raises:
            TypeError: 当列表中包含不支持的类型时
        """
        if model_list is None:
            return model_list

        row_ids = []
        for model in model_list:
            if isinstance(model, str):
                row_ids.append(model)  # just link
            elif isinstance(model, cls.MODEL_CLASS):
                row_id = cls.update_or_create(model)
                row_ids.append(row_id)
            else:
                raise TypeError(
                    f"Unsupported {cls.__name__} data type: {type(model).__name__}. "
                    f"Expected str or {cls.MODEL_CLASS.__name__}"
                )

        return row_ids

    @classmethod
    def _load_relations(cls, model: T, include_system_fields: bool = True) -> T:
        """加载关联数据（子类可覆盖）

        Args:
            model: 模型实例
            include_system_fields: 是否包含系统字段

        Returns:
            加载了关联数据的模型实例
        """
        return model

    @classmethod
    def _prepare_for_save(cls, model: T) -> T:
        """保存前准备（子类可覆盖）

        Args:
            model: 模型实例

        Returns:
            准备好的模型实例
        """
        return model


class BaseSimpleEntity(ABC):
    """简化的工作表实体基类（不使用模型）"""

    WORKSHEET_ID: str

    @classmethod
    def list(cls, filter_dict: dict) -> List[Dict]:
        """列表查询

        Args:
            filter_dict: 过滤条件字典

        Returns:
            字典列表
        """
        return WorksheetRow.list(cls.WORKSHEET_ID, filter_dict, include_system_fields=False)

    @classmethod
    def get(cls, row_id: str) -> Dict:
        """获取单条记录

        Args:
            row_id: 记录ID

        Returns:
            字典
        """
        return WorksheetRow.get(cls.WORKSHEET_ID, row_id, include_system_fields=False)

    @classmethod
    def create(cls, fields: List[Dict]) -> str:
        """创建记录

        Args:
            fields: 字段列表

        Returns:
            新创建的记录ID
        """
        return WorksheetRow.create(cls.WORKSHEET_ID, fields)

    @classmethod
    def update(cls, row_id: str, fields: List[Dict]) -> str:
        """更新记录

        Args:
            row_id: 记录ID
            fields: 字段列表

        Returns:
            更新的记录ID
        """
        return WorksheetRow.update(cls.WORKSHEET_ID, row_id, fields)
