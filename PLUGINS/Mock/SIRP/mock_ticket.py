from PLUGINS.SIRP.sirpcoremodel import TicketStatus, TicketType, TicketModel

ticket_jira = TicketModel(
    status=TicketStatus.IN_PROGRESS,
    type=TicketType.JIRA,
    title='[Security] Investigate Phishing Campaign SEC-1234',
    uid='SEC-1234',
    src_url='https://jira.example.com/browse/SEC-1234'
)
ticket_servicenow = TicketModel(
    status=TicketStatus.RESOLVED,
    type=TicketType.SERVICENOW,
    title='CRITICAL: Active Lateral Movement Detected',
    uid='INC001002',
    src_url='https://servicenow.example.com/nav_to.do?uri=incident.do?sys_id=INC001002'
)
ticket_pagerduty = TicketModel(
    status=TicketStatus.NOTIFIED,
    type=TicketType.PAGERDUTY,
    title='P1: Ransomware Encryption Activity Detected',
    uid='PD-INC-789456',
    src_url='https://example.pagerduty.com/incidents/PD-INC-789456'
)
ticket_slack = TicketModel(
    status=TicketStatus.NEW,
    type=TicketType.SLACK,
    title='Security Alert: Suspicious Cloud Activity',
    uid='SLACK-2024-001',
    src_url='https://example.slack.com/archives/C01234/p1674567890123456'
)
