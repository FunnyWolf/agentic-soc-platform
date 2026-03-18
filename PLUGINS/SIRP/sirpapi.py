from typing import List, Union

import requests

from Lib.log import logger
from PLUGINS.SIRP.CONFIG import SIRP_NOTICE_WEBHOOK
from PLUGINS.SIRP.nocolyapi import WorksheetRow
from PLUGINS.SIRP.nocolymodel import AccountModel, Condition, Group, Operator
from PLUGINS.SIRP.sirpbase import BaseWorksheetEntity
from PLUGINS.SIRP.sirpmodel import EnrichmentModel, ArtifactModel, AlertModel, CaseModel, TicketModel, MessageModel, PlaybookModel, PlaybookJobStatus, \
    KnowledgeAction, KnowledgeModel, Severity, Confidence, PlaybookType


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
    def create_from_sync(
            cls,
            uid: str,
            title: str = "",
            status=None,
            type=None,
            src_url: str = "",
            case_id: Union[str, None] = None
    ) -> str:
        ticket_new = TicketModel()
        ticket_new.uid = uid
        ticket_new.title = title
        ticket_new.status = status
        ticket_new.type = type
        ticket_new.src_url = src_url

        rowid = cls.create(ticket_new)

        if case_id:
            case_old = Case.get_by_id(case_id, lazy_load=True)
            if not case_old:
                return rowid

            case_new = CaseModel()
            case_new.rowid = case_old.rowid
            tickets = case_old.tickets or []
            if rowid not in tickets:
                tickets = [*tickets, rowid]
            case_new.tickets = tickets
            Case.update(case_new)

        return rowid

    @classmethod
    def update_from_sync(
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
        ticket_new.rowid = ticket_old.rowid
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
    def append_enrichment(
            cls,
            artifact_id: str,
            name: str = "",
            type: str = "Other",
            provider: str = "Other",
            value: str = "",
            src_url: str = "",
            desc: str = "",
            data: str = ""
    ) -> Union[str, None]:
        artifact_old = cls.get_by_id(artifact_id, lazy_load=True)
        if not artifact_old:
            return None

        enrichment_new = EnrichmentModel()
        enrichment_new.name = name
        enrichment_new.type = type
        enrichment_new.provider = provider
        enrichment_new.value = value
        enrichment_new.src_url = src_url
        enrichment_new.desc = desc
        enrichment_new.data = data
        enrichment_rowid = Enrichment.create(enrichment_new)

        existing_enrichments = []
        for enrichment in artifact_old.enrichments or []:
            if isinstance(enrichment, str):
                existing_enrichments.append(enrichment)
            elif enrichment.rowid:
                existing_enrichments.append(enrichment.rowid)

        artifact_new = ArtifactModel()
        artifact_new.rowid = artifact_old.rowid
        artifact_new.enrichments = [*existing_enrichments, enrichment_rowid]
        cls.update(artifact_new)

        return enrichment_rowid


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
    def update_ai_fields(
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
        alert_new.rowid = alert_old.rowid
        if severity_ai:
            alert_new.severity_ai = severity_ai
        if confidence_ai:
            alert_new.confidence_ai = confidence_ai
        if comment_ai:
            alert_new.comment_ai = comment_ai

        return cls.update(alert_new)

    @classmethod
    def get_discussions(cls, alert_id) -> Union[List[dict], None]:
        alert_model = cls.get_by_id(alert_id, lazy_load=True)
        if not alert_model:
            return None
        return WorksheetRow.get_discussions(cls.WORKSHEET_ID, alert_model.rowid)

    @classmethod
    def append_artifact(
            cls,
            alert_id: str,
            name: str = "",
            type=None,
            role=None,
            owner: str = "",
            value: str = "",
            reputation_provider: str = "",
            reputation_score=None
    ) -> Union[str, None]:
        alert_old = cls.get_by_id(alert_id, lazy_load=True)
        if not alert_old:
            return None

        artifact_new = ArtifactModel()
        artifact_new.name = name
        artifact_new.type = type
        artifact_new.role = role
        artifact_new.owner = owner
        artifact_new.value = value
        artifact_new.reputation_provider = reputation_provider
        artifact_new.reputation_score = reputation_score
        artifact_rowid = Artifact.create(artifact_new)

        existing_artifacts = []
        for artifact in alert_old.artifacts or []:
            if isinstance(artifact, str):
                existing_artifacts.append(artifact)
            elif artifact.rowid:
                existing_artifacts.append(artifact.rowid)

        alert_new = AlertModel()
        alert_new.rowid = alert_old.rowid
        alert_new.artifacts = [*existing_artifacts, artifact_rowid]
        cls.update(alert_new)

        return artifact_rowid

    @classmethod
    def append_enrichment(
            cls,
            alert_id: str,
            name: str = "",
            type: str = "Other",
            provider: str = "Other",
            value: str = "",
            src_url: str = "",
            desc: str = "",
            data: str = ""
    ) -> Union[str, None]:
        alert_old = cls.get_by_id(alert_id, lazy_load=True)
        if not alert_old:
            return None

        enrichment_new = EnrichmentModel()
        enrichment_new.name = name
        enrichment_new.type = type
        enrichment_new.provider = provider
        enrichment_new.value = value
        enrichment_new.src_url = src_url
        enrichment_new.desc = desc
        enrichment_new.data = data
        enrichment_rowid = Enrichment.create(enrichment_new)

        existing_enrichments = []
        for enrichment in alert_old.enrichments or []:
            if isinstance(enrichment, str):
                existing_enrichments.append(enrichment)
            elif enrichment.rowid:
                existing_enrichments.append(enrichment.rowid)

        alert_new = AlertModel()
        alert_new.rowid = alert_old.rowid
        alert_new.enrichments = [*existing_enrichments, enrichment_rowid]
        cls.update(alert_new)

        return enrichment_rowid


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
            model.alerts = Alert.batch_update_or_create(model.alerts)

        if model.enrichments is not None:
            model.enrichments = Enrichment.batch_update_or_create(model.enrichments)

        if model.tickets is not None:
            model.tickets = Ticket.batch_update_or_create(model.tickets)
        return model

    @classmethod
    def list_by_correlation_uid(cls, correlation_uid, lazy_load=False) -> List[CaseModel]:
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
        return cls.list(filter_model, lazy_load=lazy_load)

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
    def get_discussions(cls, case_id) -> Union[List[dict], None]:
        case_model = cls.get_by_id(case_id, lazy_load=True)
        if not case_model:
            return None
        return WorksheetRow.get_discussions(cls.WORKSHEET_ID, case_model.rowid)

    @classmethod
    def append_enrichment(
            cls,
            case_id: str,
            name: str = "",
            type: str = "Other",
            provider: str = "Other",
            value: str = "",
            src_url: str = "",
            desc: str = "",
            data: str = ""
    ) -> Union[str, None]:
        case_old = cls.get_by_id(case_id, lazy_load=True)
        if not case_old:
            return None

        enrichment_new = EnrichmentModel()
        enrichment_new.name = name
        enrichment_new.type = type
        enrichment_new.provider = provider
        enrichment_new.value = value
        enrichment_new.src_url = src_url
        enrichment_new.desc = desc
        enrichment_new.data = data
        enrichment_rowid = Enrichment.create(enrichment_new)

        existing_enrichments = []
        for enrichment in case_old.enrichments or []:
            if isinstance(enrichment, str):
                existing_enrichments.append(enrichment)
            elif enrichment.rowid:
                existing_enrichments.append(enrichment.rowid)

        case_new = CaseModel()
        case_new.rowid = case_old.rowid
        case_new.enrichments = [*existing_enrichments, enrichment_rowid]
        cls.update(case_new)

        return enrichment_rowid


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

    @classmethod
    def list_by_case_id(
            cls,
            case_id: str,
            job_status: Union[List[PlaybookJobStatus], None] = None
    ) -> Union[List[PlaybookModel], None]:
        case_model = Case.get_by_id(case_id, lazy_load=True)
        if not case_model:
            return None

        conditions = [
            Condition(
                field="source_worksheet",
                operator=Operator.EQ,
                value="case"
            ),
            Condition(
                field="source_rowid",
                operator=Operator.EQ,
                value=case_model.rowid
            )
        ]

        if job_status:
            conditions.append(
                Condition(
                    field="job_status",
                    operator=Operator.IN,
                    value=job_status
                )
            )

        filter_model = Group(logic="AND", children=conditions)
        return cls.list(filter_model, lazy_load=True)

    @classmethod
    def update_job_status_and_remark(cls, rowid: str, job_status: PlaybookJobStatus, remark: str) -> str:
        """更新 playbook 的 job_status 和 remark 字段

        Args:
            rowid: playbook 记录ID
            job_status: 新的作业状态
            remark: 备注信息

        Returns:
            更新后的记录ID
        """
        playbook_model_tmp = PlaybookModel()
        playbook_model_tmp.rowid = rowid
        playbook_model_tmp.job_status = job_status
        playbook_model_tmp.remark = remark

        rowid = Playbook.update(playbook_model_tmp)
        return rowid

    @classmethod
    def add_pending_playbook(cls, type: PlaybookType, name, user_input=None, source_rowid=None, record_id=None):
        if source_rowid is None:
            if record_id is None:
                raise Exception("id is required when source_rowid is None")
            else:
                if type == PlaybookType.CASE:
                    record = Case.get_by_id(record_id)
                    source_rowid = record.rowid
                elif type == PlaybookType.ALERT:
                    record = Alert.get_by_id(record_id)
                    source_rowid = record.rowid
                elif type == PlaybookType.ARTIFACT:
                    record = Artifact.get_by_id(record_id)
                    source_rowid = record.rowid

        model = PlaybookModel()
        model.source_rowid = source_rowid
        model.job_status = PlaybookJobStatus.PENDING
        model.type = type
        model.name = name
        model.user_input = user_input
        rowid = Playbook.create(model)
        return rowid


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
    def list_undone_actions(cls) -> List[KnowledgeModel]:
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
    def update_entry(
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
        knowledge_new.rowid = knowledge_old.rowid
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


class Notice(object):
    @staticmethod
    def send(user: Union[AccountModel, List[AccountModel]], title, body=None):
        if isinstance(user, AccountModel):
            users = [user]
        elif isinstance(user, list):
            users = user
        else:
            logger.error("user 参数必须是 AccountModel 实例或 AccountModel 实例列表")
            return False
        for user in users:
            result = requests.post(SIRP_NOTICE_WEBHOOK, json={"title": title, "body": body, "user": user.fullname})
        return True
