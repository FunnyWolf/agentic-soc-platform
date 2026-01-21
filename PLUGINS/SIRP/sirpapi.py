from typing import List, Dict, Union

import requests

from PLUGINS.SIRP.CONFIG import SIRP_NOTICE_WEBHOOK
from PLUGINS.SIRP.nocolymodel import AccountModel, Condition, Group, Operator
from PLUGINS.SIRP.sirpbase import BaseWorksheetEntity
from PLUGINS.SIRP.sirpmodel import EnrichmentModel, ArtifactModel, AlertModel, CaseModel, TicketModel, MessageModel, PlaybookModel, PlaybookJobStatus, \
    KnowledgeAction, KnowledgeModel


class Enrichment(BaseWorksheetEntity[EnrichmentModel]):
    """Enrichment 实体类"""
    WORKSHEET_ID = "enrichment"
    MODEL_CLASS = EnrichmentModel


class Ticket(BaseWorksheetEntity[TicketModel]):
    """Ticket 实体类"""
    WORKSHEET_ID = "ticket"
    MODEL_CLASS = TicketModel


class Artifact(BaseWorksheetEntity[ArtifactModel]):
    """Artifact 实体类 - 关联 Enrichment"""
    WORKSHEET_ID = "artifact"
    MODEL_CLASS = ArtifactModel

    @classmethod
    def _load_relations(cls, model: ArtifactModel, include_system_fields: bool = True) -> ArtifactModel:
        """加载关联的enrichments"""
        model.enrichments = Enrichment.list_by_rowids(
            model.enrichments,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        return model

    @classmethod
    def _prepare_for_save(cls, model: ArtifactModel) -> ArtifactModel:
        """保存前处理关联数据"""
        if model.enrichments is not None:
            model.enrichments = Enrichment.batch_update(model.enrichments)
        return model


class Alert(BaseWorksheetEntity[AlertModel]):
    """Alert 实体类 - 关联 Artifact 和 Enrichment"""
    WORKSHEET_ID = "alert"
    MODEL_CLASS = AlertModel

    @classmethod
    def _load_relations(cls, model: AlertModel, include_system_fields: bool = True) -> AlertModel:
        """加载关联的artifacts和enrichments"""
        model.artifacts = Artifact.list_by_rowids(
            model.artifacts,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        model.enrichments = Enrichment.list_by_rowids(
            model.enrichments,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        return model

    @classmethod
    def _prepare_for_save(cls, model: AlertModel) -> AlertModel:
        """保存前处理关联数据"""
        if model.artifacts is not None:
            model.artifacts = Artifact.batch_update(model.artifacts)

        if model.enrichments is not None:
            model.enrichments = Enrichment.batch_update(model.enrichments)

        return model


class Case(BaseWorksheetEntity[CaseModel]):
    """Case 实体类 - 关联 Alert、Enrichment 和 Ticket"""
    WORKSHEET_ID = "case"
    MODEL_CLASS = CaseModel

    @classmethod
    def _load_relations(cls, model: CaseModel, include_system_fields: bool = True) -> CaseModel:
        """加载所有关联数据"""
        model.alerts = Alert.list_by_rowids(
            model.alerts,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        model.enrichments = Enrichment.list_by_rowids(
            model.enrichments,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        model.tickets = Ticket.list_by_rowids(
            model.tickets,
            include_system_fields=include_system_fields,
            lazy_load=False
        )
        return model

    @classmethod
    def _prepare_for_save(cls, model: CaseModel) -> CaseModel:
        """保存前处理关联数据"""
        if model.alerts is not None:
            model.alerts = Alert.batch_update(model.alerts)

        if model.enrichments is not None:
            model.enrichments = Enrichment.batch_update(model.enrichments)

        if model.tickets is not None:
            model.tickets = Ticket.batch_update(model.tickets)
        return model

    @classmethod
    def get_ai_friendly_data(cls, rowid: str) -> Dict:
        """获取LLM友好的原始数据"""
        model = cls.get(rowid, include_system_fields=True)

        # TODO : 这里可以根据需要添加清理的字段
        model.threat_hunting_report_ai = None

        data = model.model_dump(mode='json', exclude_unset=True, exclude_none=True, exclude_defaults=True)
        return data


class Message(BaseWorksheetEntity[MessageModel]):
    """Message 实体类"""
    WORKSHEET_ID = "message"
    MODEL_CLASS = MessageModel


class Playbook(BaseWorksheetEntity[PlaybookModel]):
    """PlaybookLoader 实体类"""
    WORKSHEET_ID = "playbook"
    MODEL_CLASS = PlaybookModel

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


class Knowledge(BaseWorksheetEntity[KnowledgeModel]):
    """PlaybookLoader 实体类"""
    WORKSHEET_ID = "knowledge"
    MODEL_CLASS = KnowledgeModel

    @classmethod
    def list_undone_actions(cls) -> List[KnowledgeModel]:
        """获取未完成的actions"""
        filter_model = Group(
            logic="AND",
            children=[
                Condition(
                    field="action",
                    operator=Operator.NOT_IN,
                    value=[KnowledgeAction.DONE]
                )
            ]
        )
        return cls.list(filter_model)


class Notice(object):
    @staticmethod
    def send(user: Union[AccountModel, List[AccountModel]], title, body=None):
        if isinstance(user, AccountModel):
            users = [user]
        elif isinstance(user, list):
            users = user
        else:
            raise ValueError("user 参数必须是 AccountModel 实例或 AccountModel 实例列表")

        for user in users:
            result = requests.post(SIRP_NOTICE_WEBHOOK, json={"title": title, "body": body, "user": user.fullname})
        return True
