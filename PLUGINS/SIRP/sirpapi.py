import json
from abc import ABC
from datetime import datetime, timedelta
from typing import List, Union, Annotated, Dict, Any, TypeVar, Generic, Type

from pydantic import BaseModel

from Lib.log import logger
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI
from PLUGINS.SIRP.CONFIG import SIRP_NOTICE_WEBHOOK
from PLUGINS.SIRP.nocolyapi import HTTP_SESSION, WorksheetRow
from PLUGINS.SIRP.nocolymodel import Condition, Group, Operator
from PLUGINS.SIRP.sirpbasemodel import AutoAccount, BaseSystemModel, AI_PROFILE_MCP
from PLUGINS.SIRP.sirpcoremodel import Severity, Confidence, EnrichmentModel, ArtifactModel, AlertModel, CaseModel, ArtifactType
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, PlaybookModel, KnowledgeModel


def model_to_fields(model_instance: BaseModel, exclude_unset: bool = True) -> List[Dict[str, Any]]:
    fields = []
    model_data = model_instance.model_dump(mode='json', exclude_unset=exclude_unset)
    for key, value in model_data.items():
        field_info = model_instance.model_fields.get(key)
        field_item = {
            'id': key,
            'value': value
        }
        if field_info and field_info.json_schema_extra:
            if field_info.json_schema_extra.get("type") is not None:
                field_item["type"] = field_info.json_schema_extra.get("type")
        fields.append(field_item)
    return fields


T = TypeVar('T', bound=BaseSystemModel)


class BaseSimpleEntity(ABC):
    """Simplified worksheet entity base class without model binding (简化的工作表实体基类，不使用模型)"""

    WORKSHEET_ID: str

    @classmethod
    def list(cls, filter_dict: dict) -> List[Dict]:
        """List query (列表查询)

        Args:
            filter_dict: Filter condition dictionary (过滤条件字典)

        Returns:
            List of dictionaries (字典列表)
        """
        return WorksheetRow.list(cls.WORKSHEET_ID, filter_dict, include_system_fields=False)

    @classmethod
    def get(cls, row_id: str) -> Dict:
        """Get a single record (获取单条记录)

        Args:
            row_id: Record ID (记录ID)

        Returns:
            Dictionary (字典)
        """
        return WorksheetRow.get(cls.WORKSHEET_ID, row_id, include_system_fields=False)

    @classmethod
    def create(cls, fields: List[Dict]) -> str:
        """Create a record (创建记录)

        Args:
            fields: Field list (字段列表)

        Returns:
            Newly created record ID (新创建的记录ID)
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

        fields = model_to_fields(model, exclude_unset=False)
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

        if model.row_id is None:
            fields = model_to_fields(model, exclude_unset=False)
            row_id = WorksheetRow.create(cls.WORKSHEET_ID, fields)
        else:
            fields = model_to_fields(model)
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


class Enrichment(BaseWorksheetEntity[EnrichmentModel]):
    """Enrichment 实体类"""
    WORKSHEET_ID = "enrichment"
    MODEL_CLASS = EnrichmentModel

    @classmethod
    def get_by_identity(cls, model: EnrichmentModel, lazy_load: bool = True) -> Union[EnrichmentModel, None]:
        """按 type + provider + value 查找同一个 Enrichment"""
        if model.type is None or model.provider is None or model.value is None:
            return None

        type_value = model.type.value if hasattr(model.type, "value") else model.type
        provider_value = model.provider.value if hasattr(model.provider, "value") else model.provider

        filter_model = Group(
            logic="AND",
            children=[
                Condition(field="type", operator=Operator.IN, value=[type_value]),
                Condition(field="provider", operator=Operator.IN, value=[provider_value]),
                Condition(field="value", operator=Operator.EQ, value=model.value),
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            if len(result) > 1:
                logger.warning(
                    f"More than one enrichment has the same identity: "
                    f"type={type_value}, provider={provider_value}, value={model.value}. "
                    f"Use the first row_id as canonical: {result[0].row_id}"
                )
            return result[0]
        return None

    @classmethod
    def get_by_uid(cls, uid: str, lazy_load: bool = True) -> Union[EnrichmentModel, None]:
        """按 uid 查找 Enrichment"""
        if not uid:
            return None

        filter_model = Group(
            logic="AND",
            children=[
                Condition(field="uid", operator=Operator.EQ, value=uid),
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            if len(result) > 1:
                logger.warning(
                    f"More than one enrichment has the same uid: {uid}. "
                    f"Use the first row_id as canonical: {result[0].row_id}"
                )
            return result[0]
        return None

    @classmethod
    def create(cls, model: EnrichmentModel) -> str:
        if model.uid:
            existing = cls.get_by_uid(model.uid, lazy_load=True)
        else:
            existing = cls.get_by_identity(model, lazy_load=True)
        if existing and existing.row_id:
            model.row_id = existing.row_id
            return super().update(model)
        return super().create(model)

    @classmethod
    def update_or_create(cls, model: EnrichmentModel) -> str:
        if model.row_id is None:
            return cls.create(model)
        return cls.update(model)


class Artifact(BaseWorksheetEntity[ArtifactModel]):
    """Artifact 实体类 - 关联 Enrichment"""
    WORKSHEET_ID = "artifact"
    MODEL_CLASS = ArtifactModel

    @staticmethod
    def normalize_value(artifact_type, value) -> str:
        """Normalize Artifact.value before identity lookup/save (保存/查重前统一 Artifact.value)."""
        if value is None:
            return value

        normalized_value = str(value).strip()
        type_value = artifact_type.value if hasattr(artifact_type, "value") else artifact_type

        if type_value in [ArtifactType.EMAIL_ADDRESS.value, ArtifactType.EMAIL.value, ArtifactType.HASH.value]:
            return normalized_value.lower()
        if type_value == ArtifactType.HOSTNAME.value:
            return normalized_value.lower().rstrip(".")
        if type_value == ArtifactType.MAC_ADDRESS.value:
            return normalized_value.lower().replace("-", ":")
        return normalized_value

    @classmethod
    def get_by_identity(cls, model: ArtifactModel, lazy_load: bool = True) -> Union[ArtifactModel, None]:
        """按 name + type + role + value 查找同一个 Artifact"""
        if model.name is None or model.type is None or model.role is None or model.value is None:
            return None

        model.value = cls.normalize_value(model.type, model.value)

        name_value = model.name.value if hasattr(model.name, "value") else model.name
        type_value = model.type.value if hasattr(model.type, "value") else model.type
        role_value = model.role.value if hasattr(model.role, "value") else model.role

        filter_model = Group(
            logic="AND",
            children=[
                Condition(field="name", operator=Operator.EQ, value=name_value),
                Condition(field="type", operator=Operator.IN, value=[type_value]),
                Condition(field="role", operator=Operator.IN, value=[role_value]),
                Condition(field="value", operator=Operator.EQ, value=model.value),
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            if len(result) > 1:
                logger.warning(
                    f"More than one artifact has the same identity: "
                    f"name={name_value}, type={type_value}, role={role_value}, value={model.value}. "
                    f"Use the first row_id as canonical: {result[0].row_id}"
                )
            return result[0]
        return None

    @classmethod
    def create(cls, model: ArtifactModel) -> str:
        model.value = cls.normalize_value(model.type, model.value)
        existing = cls.get_by_identity(model, lazy_load=True)
        if existing and existing.row_id:
            return existing.row_id
        return super().create(model)

    @classmethod
    def update_or_create(cls, model: ArtifactModel) -> str:
        if model.row_id is None:
            return cls.create(model)
        if "value" in model.model_fields_set:
            model.value = cls.normalize_value(model.type, model.value)
        return cls.update(model)

    @classmethod
    def _load_relations(cls, model: ArtifactModel, include_system_fields: bool = True) -> ArtifactModel:
        """加载关联的enrichments"""
        if not model.enrichments:
            model.enrichments = []
            return model
        model.enrichments = Enrichment.list_by_row_ids(
            row_ids=model.enrichments,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        return model

    @classmethod
    def _prepare_for_save(cls, model: ArtifactModel) -> ArtifactModel:
        """保存前处理关联数据"""
        if model.enrichments is not None:
            model.enrichments = Enrichment.batch_update_or_create(model.enrichments)
        return model

    @classmethod
    def get_by_id(cls, artifact_id, lazy_load=False) -> Union[ArtifactModel, None]:
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="id",
                    operator=Operator.EQ,
                    value=artifact_id
                )
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            return result[0]
        else:
            return None

    @classmethod
    def attach_enrichment(
            cls,
            artifact_id: str,
            enrichment_row_id: str
    ) -> Union[str, None]:
        artifact_old = cls.get_by_id(artifact_id, lazy_load=True)
        if not artifact_old:
            return None

        existing_enrichments = []
        for enrichment in artifact_old.enrichments or []:
            if isinstance(enrichment, str):
                existing_enrichments.append(enrichment)
            elif enrichment.row_id:
                existing_enrichments.append(enrichment.row_id)

        if enrichment_row_id in existing_enrichments:
            return enrichment_row_id

        artifact_new = ArtifactModel()
        artifact_new.row_id = artifact_old.row_id
        artifact_new.enrichments = [*existing_enrichments, enrichment_row_id]
        cls.update(artifact_new)

        return enrichment_row_id


class Alert(BaseWorksheetEntity[AlertModel]):
    """Alert 实体类 - 关联 Artifact 和 Enrichment"""
    WORKSHEET_ID = "alert"
    MODEL_CLASS = AlertModel

    @classmethod
    def _load_relations(cls, model: AlertModel, include_system_fields: bool = True) -> AlertModel:
        """加载关联的artifacts和enrichments"""
        model.artifacts = Artifact.list_by_row_ids(
            model.artifacts,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        model.enrichments = Enrichment.list_by_row_ids(
            model.enrichments,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        return model

    @classmethod
    def _prepare_for_save(cls, model: AlertModel) -> AlertModel:
        """保存前处理关联数据"""
        if model.artifacts is not None:
            model.artifacts = Artifact.batch_update_or_create(model.artifacts)

        if model.enrichments is not None:
            model.enrichments = Enrichment.batch_update_or_create(model.enrichments)

        return model

    @classmethod
    def get_by_id(cls, alert_id, lazy_load=False) -> Union[AlertModel, None]:
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="id",
                    operator=Operator.EQ,
                    value=alert_id
                )
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            return result[0]
        else:
            return None

    @classmethod
    def get_discussions(cls, alert_id) -> Union[List[dict], None]:
        alert_model = cls.get_by_id(alert_id, lazy_load=True)
        if not alert_model:
            return None
        return WorksheetRow.get_discussions(cls.WORKSHEET_ID, alert_model.row_id)

    @classmethod
    def attach_artifact(
            cls,
            alert_id: str,
            artifact_row_id: str
    ) -> Union[str, None]:
        alert_old = cls.get_by_id(alert_id, lazy_load=True)
        if not alert_old:
            return None

        existing_artifacts = []
        for artifact in alert_old.artifacts or []:
            if isinstance(artifact, str):
                existing_artifacts.append(artifact)
            elif artifact.row_id:
                existing_artifacts.append(artifact.row_id)

        if artifact_row_id in existing_artifacts:
            return artifact_row_id

        alert_new = AlertModel()
        alert_new.row_id = alert_old.row_id
        alert_new.artifacts = [*existing_artifacts, artifact_row_id]
        cls.update(alert_new)

        return artifact_row_id

    @classmethod
    def attach_enrichment(
            cls,
            alert_id: str,
            enrichment_row_id: str
    ) -> Union[str, None]:
        alert_old = cls.get_by_id(alert_id, lazy_load=True)
        if not alert_old:
            return None

        existing_enrichments = []
        for enrichment in alert_old.enrichments or []:
            if isinstance(enrichment, str):
                existing_enrichments.append(enrichment)
            elif enrichment.row_id:
                existing_enrichments.append(enrichment.row_id)

        if enrichment_row_id in existing_enrichments:
            return enrichment_row_id

        alert_new = AlertModel()
        alert_new.row_id = alert_old.row_id
        alert_new.enrichments = [*existing_enrichments, enrichment_row_id]
        cls.update(alert_new)

        return enrichment_row_id


class Case(BaseWorksheetEntity[CaseModel]):
    """Case 实体类 - 关联 Alert 和 Enrichment"""
    WORKSHEET_ID = "case"
    MODEL_CLASS = CaseModel
    ANALYSIS_STREAM_NAME = "CASE_ANALYSIS_QUEUE"
    DEFAULT_ANALYSIS_COOLDOWN_MINUTES = 10

    @classmethod
    def _load_relations(cls, model: CaseModel, include_system_fields: bool = True) -> CaseModel:
        """加载所有关联数据"""
        model.alerts = Alert.list_by_row_ids(
            model.alerts,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        model.enrichments = Enrichment.list_by_row_ids(
            model.enrichments,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        return model

    @classmethod
    def _prepare_for_save(cls, model: CaseModel) -> CaseModel:
        """保存前处理关联数据"""
        if model.alerts is not None:
            model.alerts = Alert.batch_update_or_create(model.alerts)

        if model.enrichments is not None:
            model.enrichments = Enrichment.batch_update_or_create(model.enrichments)

        return model

    @classmethod
    def get_by_correlation_uid(cls, correlation_uid, lazy_load=False) -> Union[CaseModel, None]:
        """根据correlation_uid查询关联的Case"""
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="correlation_uid",
                    operator=Operator.EQ,
                    value=correlation_uid
                )
            ]
        )
        cases = cls.list(filter_model, lazy_load=lazy_load)
        if len(cases) == 0:
            return None
        elif len(cases) == 1:
            return cases[0]
        elif len(cases) > 1:
            logger.warning(f"More than one case has correlation_uid : {correlation_uid}")
            return cases[0]
        return None

    @classmethod
    def get_by_id(cls, case_id, lazy_load=False) -> Union[CaseModel, None]:
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="id",
                    operator=Operator.EQ,
                    value=case_id
                )
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            return result[0]
        else:
            return None

    @classmethod
    def update_by_id(
            cls,
            case_id: str,
            severity: Union[Severity, None] = None,
            status=None,
            verdict=None,
            comment: Union[str, None] = None,
            summary: Union[str, None] = None,
            severity_ai: Union[Severity, None] = None,
            confidence_ai: Union[Confidence, None] = None,
            verdict_ai=None,
    ) -> Union[str, None]:
        case_old = cls.get_by_id(case_id, lazy_load=True)
        if not case_old:
            return None

        case_new = CaseModel()
        case_new.row_id = case_old.row_id
        if severity is not None:
            case_new.severity = severity
        if status is not None:
            case_new.status = status
        if verdict is not None:
            case_new.verdict = verdict
        if comment is not None:
            case_new.comment = comment
        if summary is not None:
            case_new.summary = summary
        if severity_ai is not None:
            case_new.severity_ai = severity_ai
        if confidence_ai is not None:
            case_new.confidence_ai = confidence_ai
        if verdict_ai is not None:
            case_new.verdict_ai = verdict_ai

        return cls.update(case_new)

    @classmethod
    def get_discussions_by_id(cls, case_id) -> Union[List[dict], None]:
        case_model = cls.get_by_id(case_id, lazy_load=True)
        if not case_model:
            return None
        return WorksheetRow.get_discussions(cls.WORKSHEET_ID, case_model.row_id)

    @classmethod
    def get_discussions_by_row_id(cls, row_id: str) -> Union[List[dict], None]:
        return WorksheetRow.get_discussions(cls.WORKSHEET_ID, row_id)

    @classmethod
    def attach_enrichment(
            cls,
            case_id: str,
            enrichment_row_id: str
    ) -> Union[str, None]:
        case_old = cls.get_by_id(case_id, lazy_load=True)
        if not case_old:
            return None

        existing_enrichments = []
        for enrichment in case_old.enrichments or []:
            if isinstance(enrichment, str):
                existing_enrichments.append(enrichment)
            elif enrichment.row_id:
                existing_enrichments.append(enrichment.row_id)

        if enrichment_row_id in existing_enrichments:
            return enrichment_row_id

        case_new = CaseModel()
        case_new.row_id = case_old.row_id
        case_new.enrichments = [*existing_enrichments, enrichment_row_id]
        cls.update(case_new)

        return enrichment_row_id

    @classmethod
    def mark_analysis_requested(
            cls,
            row_id: str,
            cooldown_minutes: int = DEFAULT_ANALYSIS_COOLDOWN_MINUTES,
    ) -> Union[str, None]:
        """
        Case analysis scheduling model / 案件分析调度模型

        This scheduler intentionally avoids an explicit status machine such as
        IDLE / COOLING_DOWN / QUEUED / RUNNING.
        这里刻意不再使用 IDLE / COOLING_DOWN / QUEUED / RUNNING 这类显式状态机。

        Instead, scheduling is derived from a small set of fields:
        当前调度语义由少量字段组合表达：

        - analysis_next_run_at:
          The earliest time when the pending request becomes eligible for enqueue.
          当前待处理请求最早可以进入队列的时间。

        - analysis_queue_message_id:
          Non-empty means a queue message is already representing this case.
          非空表示当前已经有一条队列消息代表这个案件。

        - analysis_last_started_at:
          The latest time an analysis run actually started.
          最近一次分析真正开始执行的时间。

        - analysis_last_completed_at:
          The latest time an analysis run finished successfully.
          最近一次分析成功完成的时间。

        Core rules / 核心规则:

        1. Every meaningful case update should call mark_analysis_requested().
           每次有意义的案件变化，都应再次调用 mark_analysis_requested()。

        2. The first pending request owns analysis_next_run_at.
           First request wins; later requests in the same pending window do not overwrite it.
           第一条待处理请求负责写入 analysis_next_run_at；
           同一等待窗口内后续请求不能覆盖它。

        3. Later requests do not overwrite an existing next_run_at.
           This prevents repeated updates from pushing the pending run forever.
           后续请求不会覆盖已存在的 next_run_at，
           这样可以防止频繁更新把待执行任务不断向后推迟。

        4. When a worker starts, mark_analysis_started() clears the current
           analysis_next_run_at and queue_message_id, meaning the current pending
           schedule has been consumed.
           worker 开始时，mark_analysis_started() 会清掉当前的
           analysis_next_run_at 和 queue_message_id，
           表示这一轮待执行计划已经被消费。

        5. If the case changes again during execution, a later
           mark_analysis_requested() call will create a fresh next_run_at for the
           next round.
           如果运行期间案件再次变化，后续新的 mark_analysis_requested()
           会为下一轮重新创建 next_run_at。

        6. mark_analysis_completed() only records completion time, and
           mark_analysis_failed() only releases queue occupancy.
           There is no automatic follow-up scheduling or retry logic.
           mark_analysis_completed() 只记录完成时间，
           mark_analysis_failed() 只释放队列占位，
           不做自动补跑或自动重试。
        """
        # Entry point for all automatic case-analysis scheduling.
        # 案件分析调度的唯一入口。
        case_current = cls.get(row_id, lazy_load=True)
        if not case_current:
            logger.warning(f"Case analysis request skipped, case not found. row_id: {row_id}")
            return None

        now = datetime.now().astimezone()
        earliest_by_cooldown = None
        if case_current.analysis_last_completed_at is not None:
            # If the case was analyzed recently, the next run must not happen earlier than
            # "last completed time + cooldown". This enforces "at most once per cooldown window".
            # 如果案件刚分析过，下一次运行不能早于“上次完成时间 + 冷静期”，
            # 这样才能保证“每个冷静期窗口内最多执行一次”。
            earliest_by_cooldown = case_current.analysis_last_completed_at + timedelta(minutes=cooldown_minutes)

        # Two candidate times are considered:
        # 1. now + cooldown: debounce from the current request
        # 2. last_completed_at + cooldown: throttle from the previous completed run
        # We take the later one so the case is neither executed too frequently nor delayed forever.
        # 这里有两个候选时间：
        # 1. now + cooldown：基于当前请求的等待窗口
        # 2. last_completed_at + cooldown：基于上次完成时间的频率限制
        # 取两者较晚值，既避免过于频繁执行，也避免语义不一致。
        scheduled_next_run_at = now + timedelta(minutes=cooldown_minutes)
        if earliest_by_cooldown is not None:
            scheduled_next_run_at = max(scheduled_next_run_at, earliest_by_cooldown)

        logger.info(
            f"Case analysis request received. row_id: {row_id}, time: {now.isoformat()}, "
            f"requested_cooldown_minutes: {cooldown_minutes} "
            f"current_next_run_at: {case_current.analysis_next_run_at}, queue_message_id: {case_current.analysis_queue_message_id}, "
            f"last_started_at: {case_current.analysis_last_started_at}, last_completed_at: {case_current.analysis_last_completed_at}"
        )

        case_patch = CaseModel(row_id=row_id)

        if not case_current.analysis_next_run_at:
            # No pending schedule exists, so this request becomes the owner of next_run_at.
            # Once next_run_at is written, later requests in the same pending window must not overwrite it.
            # Only the first pending request sets next_run_at.
            # Later requests do not push the window backward.
            # 当前没有待执行计划，因此由这次请求来确定 next_run_at；
            # 一旦写入，后续同一等待窗口内的新请求不能覆盖它。
            # 只有第一条待处理请求会设置 next_run_at；
            # 后续请求不会把窗口继续往后推，避免一直分析不上。
            case_patch.analysis_next_run_at = scheduled_next_run_at
            logger.info(
                f"Case analysis request scheduled a new next_run_at. "
                f"row_id: {row_id}, time: {now.isoformat()}, next_run_at: {case_patch.analysis_next_run_at}"
            )
        else:
            # A pending schedule already exists, so this request intentionally keeps the original next_run_at.
            # 说明已经存在一条待执行计划，因此这次请求故意保留原来的 next_run_at。
            logger.info(
                f"Case analysis request kept existing next_run_at to avoid postponing the pending run. "
                f"row_id: {row_id}, time: {now.isoformat()}, existing_next_run_at: {case_current.analysis_next_run_at}"
            )
        return cls.update(case_patch)

    @classmethod
    def mark_analysis_started(cls, row_id: str, queue_message_id: str | None = None) -> Union[str, None]:
        case_current = cls.get(row_id, lazy_load=True)
        if not case_current:
            logger.warning(f"Case analysis start skipped, case not found. row_id: {row_id}")
            return None

        if queue_message_id and case_current.analysis_queue_message_id != queue_message_id:
            logger.info(
                f"Case analysis start skipped due to stale queue message. "
                f"row_id: {row_id}, case_message_id: {case_current.analysis_queue_message_id}, "
                f"queue_message_id: {queue_message_id}"
            )
            return None

        # Starting a run consumes the current pending schedule.
        # Any new request arriving during execution must create a fresh next_run_at by itself.
        # 开始分析即视为消费掉当前待执行计划；
        # 如果运行过程中又有新请求，必须由新的请求自行生成下一次 next_run_at。
        case_patch = CaseModel(
            row_id=row_id,
            analysis_queue_message_id="",
            analysis_next_run_at=None,
            analysis_last_started_at=datetime.now().astimezone(),
        )
        return cls.update(case_patch)

    @classmethod
    def mark_analysis_completed(cls, row_id: str) -> Union[str, None]:
        if not cls.get(row_id, lazy_load=True):
            logger.warning(f"Case analysis completion skipped, case not found. row_id: {row_id}")
            return None

        # Completion only records completion time.
        # It does not schedule a follow-up run; follow-up requests must come through mark_analysis_requested().
        # 分析完成只记录完成时间，不负责安排下一轮；
        # 后续如果还要再跑，必须重新调用 mark_analysis_requested()。
        completed_at = datetime.now().astimezone()
        logger.info(
            f"Case analysis completed. row_id: {row_id}, completed_at: {completed_at.isoformat()}"
        )

        case_patch = CaseModel(
            row_id=row_id,
            analysis_queue_message_id="",
            analysis_last_completed_at=completed_at,
        )
        return cls.update(case_patch)

    @classmethod
    def mark_analysis_failed(cls, row_id: str, error: str = "") -> Union[str, None]:
        if not cls.get(row_id, lazy_load=True):
            logger.warning(f"Case analysis failure skipped, case not found. row_id: {row_id}")
            return None

        # Failure only releases queue occupancy.
        # There is no automatic retry; a later external request will schedule the next run.
        # 分析失败只释放队列占位，不做自动重试；
        # 之后若还需要重跑，依赖外部再次发起请求。
        if error:
            logger.error(f"Case analysis failed, row_id: {row_id}, error: {error}")
        case_patch = CaseModel(
            row_id=row_id,
            analysis_queue_message_id="",
        )
        return cls.update(case_patch)

    @classmethod
    def promote_due_analysis_cases(cls, now: datetime | None = None) -> List[str]:
        promoted_row_ids: List[str] = []
        target_now = now or datetime.now().astimezone()
        due_cases = cls.list_cases_due_for_analysis_promotion(target_now)
        for case_current in due_cases:
            # This loop is a pure scheduler: find due cases and enqueue them once.
            # 这个循环只做调度：找到到点的案件，并确保每个案件只入队一次。
            logger.info(
                f"Case analysis promotion attempting enqueue. "
                f"row_id: {case_current.row_id}, last_started_at: {case_current.analysis_last_started_at}, "
                f"last_completed_at: {case_current.analysis_last_completed_at}, "
                f"next_run_at: {case_current.analysis_next_run_at}, trigger: scheduled_ready"
            )
            result = cls._enqueue_analysis_case(case_current.row_id, "scheduled_ready")
            if result:
                promoted_row_ids.append(case_current.row_id)
                logger.info(
                    f"Case analysis promotion succeeded. "
                    f"row_id: {case_current.row_id}, trigger: scheduled_ready, time: {target_now.isoformat()}"
                )
            else:
                logger.warning(
                    f"Case analysis promotion failed. "
                    f"row_id: {case_current.row_id}, trigger: scheduled_ready, time: {target_now.isoformat()}"
                )
        return promoted_row_ids

    @classmethod
    def list_cases_due_for_analysis_promotion(cls, now: datetime | None = None) -> List[CaseModel]:
        target_now = now or datetime.now().astimezone()
        filter_model = Group(
            logic="AND",
            children=[
                # Not currently represented by a queued message.
                # 当前没有队列中的消息占位。
                Condition(
                    field="analysis_queue_message_id",
                    operator=Operator.IS_EMPTY,
                ),
                # The scheduled time has arrived.
                # 已经到达计划执行时间。
                Condition(
                    field="analysis_next_run_at",
                    operator=Operator.LE,
                    value=target_now.strftime("%Y-%m-%d %H:%M:%S")
                ),
            ]
        )
        # Under the current scheduling invariants, these worksheet conditions are already sufficient:
        # 1. analysis_next_run_at has arrived
        # 2. no queue message is currently occupying the case
        #
        # In other words, once next_run_at exists it already represents a pending run request.
        # mark_analysis_started() consumes that request by clearing next_run_at,
        # so no extra pending marker is required.
        #
        # 按当前调度不变量，这里的工作表条件已经足够：
        # 1. analysis_next_run_at 已到时间
        # 2. 当前没有队列消息占位
        #
        # 换句话说，只要 next_run_at 存在，它本身就代表一条待执行请求；
        # mark_analysis_started() 会通过清空 next_run_at 来消费这条请求，
        # 因此不再需要额外的 pending 标记字段。
        return cls.list(filter_model, lazy_load=True)

    @classmethod
    def _enqueue_analysis_case(cls, row_id: str, trigger: str) -> Union[str, None]:
        message_id = cls._send_analysis_queue_message(row_id, trigger)
        if not message_id:
            logger.error(f"Failed to enqueue case analysis job. row_id: {row_id}")
            return None

        # Persist the latest queue message ID so the worker can reject stale messages.
        # 保存最新队列消息 ID，worker 可以据此丢弃旧消息。
        case_patch = CaseModel(
            row_id=row_id,
            analysis_queue_message_id=message_id,
        )
        return cls.update(case_patch)

    @classmethod
    def _send_analysis_queue_message(cls, row_id: str, trigger: str) -> Union[str, None]:
        return RedisStreamAPI().send_message(
            cls.ANALYSIS_STREAM_NAME,
            {
                "case_row_id": row_id,
                "trigger": trigger,
            }
        )


class Playbook(BaseWorksheetEntity[PlaybookModel]):
    """PlaybookLoader 实体类"""
    WORKSHEET_ID = "playbook"
    MODEL_CLASS = PlaybookModel

    @classmethod
    def get_by_id(cls, playbook_id, lazy_load=False) -> Union[PlaybookModel, None]:
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="id",
                    operator=Operator.EQ,
                    value=playbook_id
                )
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            return result[0]
        else:
            return None

    @classmethod
    def list_pending_playbooks(cls) -> List[PlaybookModel]:
        """获取待处理的playbooks"""

        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="job_status",
                    operator=Operator.IN,
                    value=[PlaybookJobStatus.PENDING]
                )
            ]
        )

        return cls.list(filter_model, lazy_load=True)

    @classmethod
    def update_job_status_and_remark(cls, row_id: str, job_status: PlaybookJobStatus, remark: str) -> str:
        """更新 playbook 的 job_status 和 remark 字段

        Args:
            row_id: playbook 记录ID
            job_status: 新的作业状态
            remark: 备注信息

        Returns:
            更新后的记录ID
        """
        playbook_model_tmp = PlaybookModel()
        playbook_model_tmp.row_id = row_id
        playbook_model_tmp.job_status = job_status
        playbook_model_tmp.remark = remark

        row_id = Playbook.update(playbook_model_tmp)
        return row_id

    @classmethod
    def add_pending_playbook(cls, name, user_input=None, row_id=None, case_id=None) -> PlaybookModel:
        if row_id is None:
            if case_id is None:
                raise Exception("case_id is required when row_id is None")
            record = Case.get_by_id(case_id)
            row_id = record.row_id

        model = PlaybookModel()
        model.source_row_id = row_id
        model.job_status = PlaybookJobStatus.PENDING
        model.name = name
        model.user_input = user_input
        row_id = Playbook.create(model)
        model_create = Playbook.get(row_id, lazy_load=True)
        return model_create


class Knowledge(BaseWorksheetEntity[KnowledgeModel]):
    """PlaybookLoader 实体类"""
    WORKSHEET_ID = "knowledge"
    MODEL_CLASS = KnowledgeModel

    @classmethod
    def get_by_id(cls, knowledge_id, lazy_load=False) -> Union[KnowledgeModel, None]:
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="id",
                    operator=Operator.EQ,
                    value=knowledge_id
                )
            ]
        )
        result = cls.list(filter_model, lazy_load=lazy_load)
        if result:
            return result[0]
        else:
            return None

    @classmethod
    def update_by_id(
            cls,
            knowledge_id: str,
            title: Union[str, None] = None,
            body: Union[str, None] = None,
            expires_at=None,
            source=None,
            tags: Union[List[str], None] = None
    ) -> Union[str, None]:
        knowledge_old = cls.get_by_id(knowledge_id, lazy_load=True)
        if not knowledge_old:
            return None

        update_data = {"row_id": knowledge_old.row_id}
        if title is not None:
            update_data["title"] = title
        if body is not None:
            update_data["body"] = body
        if expires_at is not None:
            update_data["expires_at"] = expires_at
        if source is not None:
            update_data["source"] = source
        if tags is not None:
            update_data["tags"] = tags

        knowledge_new = KnowledgeModel(**update_data)
        return cls.update(knowledge_new)

    @classmethod
    def search_models(cls, keywords: List[str], limit: int = 10) -> List[KnowledgeModel]:
        """
        Search Knowledge records by keywords.
        按关键词搜索 Knowledge 记录。

        Args:
            keywords: Keyword list. Records matching at least one keyword are returned.
                关键词列表。返回匹配至少一个关键词的记录。
            limit: Maximum number of KnowledgeModel records to return.
                最多返回的 KnowledgeModel 记录数量。

        Returns:
            Unexpired KnowledgeModel records whose title or body contains any keyword.
            title 或 body 包含任意关键词且未过期的 KnowledgeModel 记录。

        Raises:
            TypeError: If keywords is a string instead of a list. Use search() for public keyword search.
                当 keywords 是字符串而不是列表时抛出。公开关键词搜索请使用 search()。
        """
        logger.debug(f"knowledge search keywords : {keywords}")
        if isinstance(keywords, str):
            raise TypeError("Knowledge.search_models expects List[str]. Use Knowledge.search for one keyword or phrase.")

        normalized_keywords = []
        seen_keywords = set()
        for keyword in keywords or []:
            if not isinstance(keyword, str):
                continue
            keyword = keyword.strip()
            if not keyword:
                continue
            keyword_key = keyword.casefold()
            if keyword_key in seen_keywords:
                continue
            normalized_keywords.append(keyword)
            seen_keywords.add(keyword_key)

        if not normalized_keywords:
            return []

        keyword_conditions = []
        for keyword in normalized_keywords:
            keyword_conditions.append(Condition(field="title", operator=Operator.CONTAINS, value=keyword))
            keyword_conditions.append(Condition(field="body", operator=Operator.CONTAINS, value=keyword))

        now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        filter_model = Group(
            logic="AND",
            children=[
                Group(logic="OR", children=keyword_conditions),
                Group(
                    logic="OR",
                    children=[
                        Condition(field="expires_at", operator=Operator.IS_EMPTY),
                        Condition(field="expires_at", operator=Operator.GE, value=now),
                    ]
                )
            ]
        )
        models = cls.list(filter_model, lazy_load=True)
        limited_models = models[:limit]
        return limited_models

    @classmethod
    def search(
            cls,
            keyword: Annotated[Union[str, List[str]], "Search keyword or keyword list."],
            limit: int = 10
    ) -> Annotated[
        str, "relevant knowledge entries, policies, and special handling instructions."]:
        """
        Search the internal knowledge base by keyword and return a JSON list string.
        按关键词搜索内部知识库，并返回 JSON 列表字符串。

        Args:
            keyword: A keyword string or a keyword list. When a list is provided, records matching at least one item are returned.
                关键词字符串或关键词列表。传入列表时，返回匹配至少一个列表项的记录。
            limit: Maximum number of knowledge records to return.
                最多返回的知识记录数量。

        Returns:
            JSON list string containing relevant unexpired knowledge entries.
            包含相关且未过期知识记录的 JSON 列表字符串。
        """
        if isinstance(keyword, str):
            keywords = [keyword]
        elif isinstance(keyword, list):
            keywords = keyword
        else:
            raise TypeError("Knowledge.search expects str or List[str].")

        models = cls.search_models(keywords, limit=limit)
        result_all = [model.model_dump_for_ai(profile=AI_PROFILE_MCP) for model in models]

        results = json.dumps(result_all, ensure_ascii=False)
        logger.debug(f"Knowledge search results : {results}")
        return results


class Notice(object):
    @staticmethod
    def send(user: AutoAccount, title, body=None):
        if isinstance(user, AutoAccount):
            users = [user]
        elif isinstance(user, list):
            users = user
        else:
            logger.error("user 参数必须是 AutoAccount 实例或 AutoAccount 实例列表")
            return False
        for user in users:
            result = HTTP_SESSION.post(SIRP_NOTICE_WEBHOOK, json={"title": title, "body": body, "user": user})
        return True
