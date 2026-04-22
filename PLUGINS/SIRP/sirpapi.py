import json
from abc import ABC
from typing import List, Union, Annotated, Dict, Any, TypeVar, Generic, Type

import requests
from langchain_core.documents import Document
from pydantic import BaseModel

from Lib.log import logger
from PLUGINS.Embeddings.embeddings_qdrant import get_qdrant_embeddings_api, SIRP_KNOWLEDGE_COLLECTION
from PLUGINS.SIRP.CONFIG import SIRP_NOTICE_WEBHOOK
from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.nocolymodel import Condition, Group, Operator
from PLUGINS.SIRP.sirpbasemodel import AutoAccount, BaseSystemModel
from PLUGINS.SIRP.sirpcoremodel import Severity, Confidence, EnrichmentModel, TicketModel, ArtifactModel, AlertModel, CaseModel
from PLUGINS.SIRP.sirpextramodel import PlaybookType, PlaybookJobStatus, KnowledgeAction, MessageModel, PlaybookModel, KnowledgeModel


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


T = TypeVar('T', bound=BaseSystemModel)


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


class Enrichment(BaseWorksheetEntity[EnrichmentModel]):
    """Enrichment 实体类"""
    WORKSHEET_ID = "enrichment"
    MODEL_CLASS = EnrichmentModel


class Ticket(BaseWorksheetEntity[TicketModel]):
    """Ticket 实体类"""
    WORKSHEET_ID = "ticket"
    MODEL_CLASS = TicketModel

    @classmethod
    def get_by_id(cls, ticket_id, lazy_load=False) -> Union[TicketModel, None]:
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="id",
                    operator=Operator.EQ,
                    value=ticket_id
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
            ticket_id: str,
            uid: Union[str, None] = None,
            title: Union[str, None] = None,
            status=None,
            type=None,
            src_url: Union[str, None] = None
    ) -> Union[str, None]:
        ticket_old = cls.get_by_id(ticket_id, lazy_load=True)
        if not ticket_old:
            return None

        ticket_new = TicketModel()
        ticket_new.row_id = ticket_old.row_id
        if uid is not None:
            ticket_new.uid = uid
        if title is not None:
            ticket_new.title = title
        if status is not None:
            ticket_new.status = status
        if type is not None:
            ticket_new.type = type
        if src_url is not None:
            ticket_new.src_url = src_url

        return cls.update(ticket_new)


class Artifact(BaseWorksheetEntity[ArtifactModel]):
    """Artifact 实体类 - 关联 Enrichment"""
    WORKSHEET_ID = "artifact"
    MODEL_CLASS = ArtifactModel

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
    def update_by_id(
            cls,
            alert_id: str,
            severity_ai: Union[Severity, None] = None,
            confidence_ai: Union[Confidence, None] = None,
            comment_ai: Union[str, None] = None
    ) -> Union[str, None]:
        alert_old = cls.get_by_id(alert_id, lazy_load=True)
        if not alert_old:
            return None

        alert_new = AlertModel()
        alert_new.row_id = alert_old.row_id
        if severity_ai is not None:
            alert_new.severity_ai = severity_ai
        if confidence_ai is not None:
            alert_new.confidence_ai = confidence_ai
        if comment_ai is not None:
            alert_new.comment_ai = comment_ai

        return cls.update(alert_new)

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
    """Case 实体类 - 关联 Alert、Enrichment 和 Ticket"""
    WORKSHEET_ID = "case"
    MODEL_CLASS = CaseModel

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
        model.tickets = Ticket.list_by_row_ids(
            model.tickets,
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

        if model.tickets is not None:
            model.tickets = Ticket.batch_update_or_create(model.tickets)
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
            severity_ai: Union[Severity, None] = None,
            confidence_ai: Union[Confidence, None] = None,
            attack_stage_ai=None,
            comment_ai: Union[str, None] = None,
            verdict_ai=None,
            summary_ai: Union[str, None] = None
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
        if severity_ai is not None:
            case_new.severity_ai = severity_ai
        if confidence_ai is not None:
            case_new.confidence_ai = confidence_ai
        if attack_stage_ai is not None:
            case_new.attack_stage_ai = attack_stage_ai
        if comment_ai is not None:
            case_new.comment_ai = comment_ai
        if verdict_ai is not None:
            case_new.verdict_ai = verdict_ai
        if summary_ai is not None:
            case_new.summary_ai = summary_ai

        return cls.update(case_new)

    @classmethod
    def get_discussions(cls, case_id) -> Union[List[dict], None]:
        case_model = cls.get_by_id(case_id, lazy_load=True)
        if not case_model:
            return None
        return WorksheetRow.get_discussions(cls.WORKSHEET_ID, case_model.row_id)

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
    def attach_ticket(
            cls,
            case_id: str,
            ticket_row_id: str
    ) -> Union[str, None]:
        case_old = cls.get_by_id(case_id, lazy_load=True)
        if not case_old:
            return None

        existing_tickets = []
        for ticket in case_old.tickets or []:
            if isinstance(ticket, str):
                existing_tickets.append(ticket)
            elif ticket.row_id:
                existing_tickets.append(ticket.row_id)

        if ticket_row_id in existing_tickets:
            return ticket_row_id

        case_new = CaseModel()
        case_new.row_id = case_old.row_id
        case_new.tickets = [*existing_tickets, ticket_row_id]
        cls.update(case_new)

        return ticket_row_id


class Message(BaseWorksheetEntity[MessageModel]):
    """Message 实体类"""
    WORKSHEET_ID = "message"
    MODEL_CLASS = MessageModel


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
    def add_pending_playbook(cls, type: PlaybookType, name, user_input=None, source_row_id=None, record_id=None) -> PlaybookModel:
        if source_row_id is None:
            if record_id is None:
                raise Exception("id is required when source_row_id is None")
            else:
                if type == PlaybookType.CASE:
                    record = Case.get_by_id(record_id)
                    source_row_id = record.row_id
                elif type == PlaybookType.ALERT:
                    record = Alert.get_by_id(record_id)
                    source_row_id = record.row_id
                elif type == PlaybookType.ARTIFACT:
                    record = Artifact.get_by_id(record_id)
                    source_row_id = record.row_id

        model = PlaybookModel()
        model.source_row_id = source_row_id
        model.job_status = PlaybookJobStatus.PENDING
        model.type = type
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
    def list_undone_action_records(cls) -> List[KnowledgeModel]:
        """获取未完成的actions"""
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="action",
                    operator=Operator.IN,
                    value=[KnowledgeAction.STORE, KnowledgeAction.REMOVE]
                )
            ]
        )
        return cls.list(filter_model)

    @classmethod
    def update_by_id(
            cls,
            knowledge_id: str,
            title: Union[str, None] = None,
            body: Union[str, None] = None,
            using: Union[bool, None] = None,
            action=None,
            source=None,
            tags: Union[List[str], None] = None
    ) -> Union[str, None]:
        knowledge_old = cls.get_by_id(knowledge_id, lazy_load=True)
        if not knowledge_old:
            return None

        knowledge_new = KnowledgeModel()
        knowledge_new.row_id = knowledge_old.row_id
        if title is not None:
            knowledge_new.title = title
        if body is not None:
            knowledge_new.body = body
        if using is not None:
            knowledge_new.using = using
        if action is not None:
            knowledge_new.action = action
        if source is not None:
            knowledge_new.source = source
        if tags is not None:
            knowledge_new.tags = tags

        return cls.update(knowledge_new)

    @classmethod
    def search(cls, query: Annotated[str, "The search query."]) -> Annotated[
        str, "relevant knowledge entries, policies, and special handling instructions."]:
        """
        Search the internal knowledge base for specific entities, business-specific logic, SOPs, or historical context.
        """
        logger.debug(f"knowledge search : {query}")
        threshold = 0.5
        result_all = []
        docs_qdrant = get_qdrant_embeddings_api().search_documents_with_rerank(collection_name=SIRP_KNOWLEDGE_COLLECTION, query=query, k=10, top_n=3)
        logger.debug(docs_qdrant)
        for doc in docs_qdrant:
            doc: Document
            if doc.metadata["rerank_score"] >= threshold:
                result_all.append(doc.page_content)

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
            result = requests.post(SIRP_NOTICE_WEBHOOK, json={"title": title, "body": body, "user": user})
        return True
