import {
    ApiOutlined,
    BlockOutlined,
    CheckCircleOutlined,
    FileTextOutlined,
    PauseCircleOutlined,
    PlayCircleOutlined,
    PlusCircleOutlined,
    StopOutlined,
    SyncOutlined,
    UserOutlined,
} from '@ant-design/icons'
import {BookOpenText, BrainCircuit, BriefcaseBusiness, Fingerprint, Siren, WandSparkles} from 'lucide-react'
import AlertBasicView from '../components/AlertBasicView'
import ArtifactBasicView from '../components/ArtifactBasicView'
import CaseBasicView from '../components/CaseBasicView'
import CaseInvestigationView from '../components/CaseInvestigationView'
import CaseKnowledgeView from '../components/CaseKnowledgeView'
import CasePlaybookAction from '../components/CasePlaybookRunModal'
import EnrichmentBasicView from '../components/EnrichmentBasicView'
import KnowledgeBasicView from '../components/KnowledgeBasicView'
import OverflowTags from '../components/OverflowTags'
import PlaybookBasicView from '../components/PlaybookBasicView'
import RelatedEnrichmentsTable, {type EnrichmentTargetType} from '../components/RelatedEnrichmentsTable'
import RelatedRecordsTable from '../components/RelatedRecordsTable'
import UserAvatar from '../components/UserAvatar'
import type {AdvancedFilterFieldConfig, OpenResourceOptions, ResourceColumn, ResourceConfig} from '../types/records'
import {typography} from '../utils/typography'
import {
    alertActionTag,
    alertAnalyticTypeTag,
    alertDispositionTag,
    artifactRoleTag,
    caseCategoryTag,
    choiceTag,
    emptyValue,
    emptyValueNode,
    formatDateTime,
    knowledgeSourceTag,
    productCategoryTag,
    severityTag,
    statusTag,
    verdictTag
} from '../utils/recordDisplay'

type RecordRow = Record<string, unknown>
type RecordTabRenderOptions = {
    onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
    onChanged?: () => void
}

const lucideIconProps = {size: '1em', strokeWidth: 2}
const value = (record: RecordRow, key: string) => record[key]
const stringValue = (record: RecordRow, key: string) => emptyValue(value(record, key))
const viewRelatedLabel = (count: unknown) => (
    <span style={{display: 'inline-flex', alignItems: 'center', gap: 4}}>
        <BlockOutlined/>
        {`View (${Number(count || 0)})`}
    </span>
)
const playbookCaseLabel = (record: RecordRow) => {
    const readableId = stringValue(record, 'case_readable_id')
    const title = stringValue(record, 'case_title')
    if (readableId === '—') return title
    if (title === '—') return readableId
    return `${readableId.toUpperCase()} / ${title}`
}
const linkedObjectResourceKey = (record: RecordRow) => {
    const model = String(value(record, 'content_type_model') || '')
    const resources: Record<string, string> = {
        case: 'cases',
        alert: 'alerts',
        artifact: 'artifacts',
    }
    return resources[model]
}
const upperStringValue = (record: RecordRow, key: string) => {
    const displayValue = stringValue(record, key)
    return displayValue === '—' ? displayValue : displayValue.toUpperCase()
}
const date = (field: string) => (_: unknown, record: RecordRow) => formatDateTime(String(value(record, field) || ''))
const confidenceTag = (v: unknown) => severityTag(String(v || ''))
const priorityTag = (v: unknown) => severityTag(String(v || ''))
const userRoleTag = (v: unknown) => {
    const role = String(v || '')
    const colors: Record<string, string> = {admin: 'purple', user: 'blue', viewer: 'default'}
    return choiceTag(role ? role[0].toUpperCase() + role.slice(1) : '', colors[role])
}
const authTypeTag = (v: unknown) => {
    const authType = String(v || '')
    return choiceTag(authType === 'ldap' ? 'LDAP' : 'Local', authType === 'ldap' ? 'geekblue' : 'green')
}
const activeStatusTag = (v: unknown) => {
    const active = v === true || v === 'true'
    return choiceTag(active ? 'Active' : 'Disabled', active ? 'green' : 'red')
}
const llmProviderStatusTag = (v: unknown) => {
    const enabled = v === true || v === 'true'
    return choiceTag(enabled ? 'Enabled' : 'Disabled', enabled ? 'green' : 'default')
}
const llmTagColors: Record<string, string> = {
    fast: 'blue',
    powerful: 'purple',
    tool_calling: 'geekblue',
    structured_output: 'green',
}
const llmTagOptions = [
    {label: 'fast', value: 'fast'},
    {label: 'powerful', value: 'powerful'},
    {label: 'tool_calling', value: 'tool_calling'},
    {label: 'structured_output', value: 'structured_output'},
]
const llmTags = (items: unknown) => {
    const tagItems = Array.isArray(items) ? items : (items ? [items] : [])
    return (
        <span style={{display: 'inline-flex', alignItems: 'center', gap: 4, flexWrap: 'wrap'}}>
            {tagItems.map((item) => {
                const tag = String(item)
                return <span key={tag}>{choiceTag(tag, llmTagColors[tag] || 'default')}</span>
            })}
        </span>
    )
}
const playbookJobStatusTag = (v: unknown) => {
    const status = String(v || '')
    const options = [
        {label: 'Success', value: 'Success', color: 'green'},
        {label: 'Failed', value: 'Failed', color: 'red'},
        {label: 'Pending', value: 'Pending', color: 'gold'},
        {label: 'Running', value: 'Running', color: 'processing'},
    ]
    const option = options.find((item) => item.value === status)
    const color = markerColor(option?.color)
    if (!status) return emptyValueNode()
    return (
        <span style={{display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 0}}>
            <span style={{color: color || 'rgba(255,255,255,0.45)', display: 'inline-flex', alignItems: 'center', fontSize: typography.tag.fontSize, flexShrink: 0}}>
                {playbookJobStatusIcon(status)}
            </span>
            <span style={{color, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{status}</span>
        </span>
    )
}
const tags = (items: unknown, color = 'blue') => <OverflowTags items={items} color={color}/>

function relatedTable(
    endpoint: string,
    tableKey: string,
    resourceKey: keyof typeof resourceConfigs,
    baseParams?: Record<string, string>,
    onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void,
) {
    const config = resourceConfigs[resourceKey]
    return (
        <RelatedRecordsTable
            endpoint={endpoint}
            tableKey={tableKey}
            resourceKey={resourceKey}
            columns={config.columns}
            filters={config.filters}
            advancedFilters={config.advancedFilters}
            baseParams={baseParams}
            onOpenResource={onOpenResource}
        />
    )
}

function relatedEnrichmentsTable(
    targetType: EnrichmentTargetType,
    record: RecordRow,
    onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void,
    onChanged?: () => void,
) {
    const config = resourceConfigs.enrichments
    const recordId = value(record, 'id')
    const targetId = recordId === null || recordId === undefined ? '' : String(recordId)

    return (
        <RelatedEnrichmentsTable
            targetType={targetType}
            targetId={targetId}
            columns={config.columns}
            filters={config.filters}
            advancedFilters={config.advancedFilters}
            onOpenResource={onOpenResource}
            onChanged={onChanged}
        />
    )
}

const column = (
    key: string,
    title: string,
    width: number,
    options: Partial<ResourceColumn<RecordRow>> = {},
): ResourceColumn<RecordRow> => ({
    key,
    title,
    dataIndex: key,
    width,
    ...options,
})

const field = (key: string, label: string, valueType: AdvancedFilterFieldConfig['valueType']): AdvancedFilterFieldConfig => ({
    key,
    label,
    valueType,
})

const emptyTabs = {
    case: [
        {
            key: 'alerts',
            label: 'Alerts',
            icon: <Siren {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => relatedTable(
                '/alerts/',
                `case-alerts:${record.id}`,
                'alerts',
                {case__id: String(record.id)},
                options?.onOpenResource,
            ),
        },
        {
            key: 'enrichments',
            label: 'Enrichments',
            icon: <WandSparkles {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => relatedEnrichmentsTable('case', record, options?.onOpenResource, options?.onChanged),
        },
        {
            key: 'knowledge',
            label: 'Knowledge',
            icon: <BookOpenText {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => (
                <CaseKnowledgeView
                    caseId={String(record.id || '')}
                    editableFields={resourceConfigs.knowledge.editableFields || []}
                    onOpenResource={options?.onOpenResource}
                    onChanged={options?.onChanged}
                />
            ),
        },
        {
            key: 'playbooks',
            label: 'Playbooks',
            icon: <BrainCircuit {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => relatedTable(
                '/playbooks/',
                `case-playbooks:${record.id}`,
                'playbooks',
                {case__id: String(record.id)},
                options?.onOpenResource,
            ),
        },
        {
            key: 'investigation',
            label: 'Investigation',
            icon: <FileTextOutlined/>,
            render: (record: RecordRow) => <CaseInvestigationView caseId={String(record.id || '')}/>,
        },
    ],
    alert: [
        {
            key: 'artifacts',
            label: 'Artifacts',
            icon: <Fingerprint {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => relatedTable(
                '/artifacts/',
                `alert-artifacts:${record.id}`,
                'artifacts',
                {alerts: String(record.id)},
                options?.onOpenResource,
            ),
        },
        {
            key: 'enrichments',
            label: 'Enrichments',
            icon: <WandSparkles {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => relatedEnrichmentsTable('alert', record, options?.onOpenResource, options?.onChanged),
        },
    ],
    artifact: [
        {
            key: 'alerts',
            label: 'Alerts',
            icon: <Siren {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => relatedTable(
                '/alerts/',
                `artifact-alerts:${record.id}`,
                'alerts',
                {artifacts: String(record.id)},
                options?.onOpenResource,
            ),
        },
        {
            key: 'enrichments',
            label: 'Enrichments',
            icon: <WandSparkles {...lucideIconProps}/>,
            render: (record: RecordRow, options?: RecordTabRenderOptions) => relatedEnrichmentsTable('artifact', record, options?.onOpenResource, options?.onChanged),
        },
    ],
}
const L80 = 80;
const L96 = 96;
const L120 = 120;
const L132 = 132;
const L160 = 160;
const L200 = 200;
const L240 = 240;
const L280 = 280;
const L360 = 360;
const L400 = 400;
const L480 = 480;
const caseStatusOptions = [
    {label: 'New', value: 'New', color: 'cyan'},
    {label: 'In Progress', value: 'In Progress', color: 'processing'},
    {label: 'On Hold', value: 'On Hold', color: 'gold'},
    {label: 'Resolved', value: 'Resolved', color: 'green'},
    {label: 'Closed', value: 'Closed', color: 'default'},
]
const markerColor = (color?: string) => {
    const colors: Record<string, string> = {
        blue: '#1677ff',
        processing: '#1677ff',
        cyan: '#13c2c2',
        gold: '#faad14',
        green: '#52c41a',
        red: '#ff4d4f',
        default: 'rgba(255,255,255,0.35)',
    }
    return color ? colors[color] || color : undefined
}
const caseStatusIcon = (status: string) => {
    if (status === 'New') return <PlusCircleOutlined/>
    if (status === 'In Progress') return <SyncOutlined spin/>
    if (status === 'On Hold') return <PauseCircleOutlined/>
    if (status === 'Resolved') return <CheckCircleOutlined/>
    if (status === 'Closed') return <StopOutlined/>
    return <UserOutlined/>
}
const playbookJobStatusIcon = (status: string) => {
    if (status === 'Success') return <CheckCircleOutlined/>
    if (status === 'Failed') return <StopOutlined/>
    if (status === 'Pending') return <PauseCircleOutlined/>
    if (status === 'Running') return <SyncOutlined spin/>
    return <PlayCircleOutlined/>
}
const caseStatusSelectLabel = (raw: unknown) => {
    const status = String(raw || '')
    const option = caseStatusOptions.find((item) => item.value === status)
    const color = markerColor(option?.color)
    if (!status) return emptyValueNode()
    return (
        <span style={{display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 0}}>
            <span style={{color: color || 'rgba(255,255,255,0.45)', display: 'inline-flex', alignItems: 'center', fontSize: typography.tag.fontSize, flexShrink: 0}}>
                {caseStatusIcon(status)}
            </span>
            <span style={{color, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{status}</span>
        </span>
    )
}
const caseVerdictOptions = [
    {label: 'Unknown', value: 'Unknown', color: 'default'},
    {label: 'False Positive', value: 'False Positive', color: 'green'},
    {label: 'True Positive', value: 'True Positive', color: 'red'},
    {label: 'Disregard', value: 'Disregard', color: 'default'},
    {label: 'Suspicious', value: 'Suspicious', color: 'orange'},
    {label: 'Benign', value: 'Benign', color: 'green'},
    {label: 'Test', value: 'Test', color: 'purple'},
    {label: 'Insufficient Data', value: 'Insufficient Data', color: 'gold'},
    {label: 'Security Risk', value: 'Security Risk', color: 'volcano'},
    {label: 'Managed Externally', value: 'Managed Externally', color: 'blue'},
    {label: 'Duplicate', value: 'Duplicate', color: 'cyan'},
    {label: 'Other', value: 'Other', color: 'default'},
]
export const resourceConfigs: Record<string, ResourceConfig<RecordRow>> = {
    cases: {
        key: 'cases',
        label: 'Cases',
        icon: <BriefcaseBusiness {...lucideIconProps}/>,
        endpoint: '/cases/',
        rowKey: 'id',
        searchPlaceholder: 'Case ID, Title, Description, Summary, Correlation UID',
        filters: [
            {key: 'status', label: 'Status', valueType: 'select', width: L160},
            {key: 'severity', label: 'Severity', valueType: 'select', width: L160},
            {key: 'assignee', label: 'Assignee', valueType: 'user', width: L160},
        ],
        advancedFilters: [
            field('case_id', 'Case ID', 'text'),
            field('title', 'Title', 'text'),
            field('status', 'Status', 'select'),
            field('category', 'Category', 'select'),
            field('severity', 'Severity', 'select'),
            field('assignee', 'Assignee', 'user'),
            field('verdict', 'Verdict', 'select'),
            field('priority', 'Priority', 'select'),
            field('confidence', 'Confidence', 'select'),
            field('impact', 'Impact', 'select'),
            field('tags', 'Tags', 'tag'),
            field('acknowledged_time', 'Acknowledged Time', 'date'),
            field('closed_time', 'Closed Time', 'date'),
            field('created_at', 'Created Time', 'date'),
            field('updated_at', 'Updated Time', 'date'),
            field('description', 'Description', 'text'),
            field('summary', 'Summary', 'text'),
            field('correlation_uid', 'Correlation UID', 'text'),
        ],
        columns: [
            column('case_id', 'Case ID', L160, {required: true, defaultVisible: true, fixed: 'left', openRecord: true, uppercase: true}),
            column('title', 'Title', L480, {required: true, defaultVisible: true, fixed: 'left'}),
            column('status', 'Status', L132, {defaultVisible: true, sorter: true, render: caseStatusSelectLabel}),
            column('alerts_link', 'Alerts', L132, {
                dataIndex: 'alert_count',
                defaultVisible: true,
                openRecordTab: 'alerts',
                render: viewRelatedLabel,
            }),
            column('playbooks_link', 'Playbooks', L132, {
                dataIndex: 'playbook_count',
                defaultVisible: true,
                openRecordTab: 'playbooks',
                render: viewRelatedLabel,
            }),
            column('enrichments_link', 'Enrichments', L132, {
                dataIndex: 'enrichment_count',
                defaultVisible: true,
                openRecordTab: 'enrichments',
                render: viewRelatedLabel,
            }),
            column('category', 'Category', L132, {defaultVisible: true, render: (v) => caseCategoryTag(String(v || ''))}),
            column('severity', 'Severity', L132, {defaultVisible: true, sorter: true, render: (v) => severityTag(String(v || ''))}),
            column('severity_ai', 'Severity (AI)', L132, {defaultVisible: true, sorter: true, render: (v) => severityTag(String(v || ''))}),
            column('confidence', 'Confidence', L132, {defaultVisible: true, sorter: true, render: confidenceTag}),
            column('confidence_ai', 'Confidence (AI)', L132, {defaultVisible: true, sorter: true, render: confidenceTag}),
            column('priority', 'Priority', L132, {defaultVisible: true, sorter: true, render: priorityTag}),
            column('priority_ai', 'Priority (AI)', L132, {defaultVisible: true, sorter: true, render: priorityTag}),
            column('impact', 'Impact', L132, {defaultVisible: true, sorter: true, render: (v) => severityTag(String(v || ''))}),
            column('impact_ai', 'Impact (AI)', L132, {defaultVisible: true, sorter: true, render: (v) => severityTag(String(v || ''))}),
            column('verdict', 'Verdict', L160, {defaultVisible: true, sorter: true, render: (v) => verdictTag(String(v || ''))}),
            column('verdict_ai', 'Verdict (AI)', L160, {defaultVisible: true, sorter: true, render: (v) => verdictTag(String(v || ''))}),
            column('assignee_name', 'Assignee', L132, {defaultVisible: true}),
            column('acknowledged_time', 'Acknowledged Time', L200, {defaultVisible: true, sorter: true, render: date('acknowledged_time')}),
            column('closed_time', 'Closed Time', L160, {defaultVisible: true, sorter: true, render: date('closed_time')}),
            column('created_at', 'Creation Time', L160, {defaultVisible: true, sorter: true, render: date('created_at')}),
            column('updated_at', 'Last Modified Time', L160, {defaultVisible: true, sorter: true, render: date('updated_at')}),
            column('tags', 'Tags', L400, {render: (v) => tags(v)}),
            column('description', 'Description', L400),
            column('summary', 'Summary', L400),
            column('correlation_uid', 'Correlation UID', L240),
        ],
        editableFields: [
            {key: 'status', type: 'select', options: caseStatusOptions},
            {key: 'acknowledged_time', type: 'datetime', emptyValue: null},
            {key: 'closed_time', type: 'datetime', emptyValue: null},
            {key: 'assignee', type: 'user', emptyValue: null},
            {key: 'verdict', type: 'text', options: caseVerdictOptions},
            {key: 'summary', type: 'markdown'},
        ],
        detailHeaderActions: CasePlaybookAction,
        basicView: (record, options) => <CaseBasicView record={record} fieldController={options?.fieldController}/>,
        basicSections: [
            {
                key: 'summary',
                title: 'Summary',
                fields: [
                    {label: 'Case ID', value: (r) => upperStringValue(r, 'case_id'), mono: true},
                    {label: 'Status', value: (r) => statusTag(String(value(r, 'status') || '')), tag: true},
                    {label: 'Title', value: (r) => stringValue(r, 'title')},
                ],
            },
            {
                key: 'risk',
                title: 'Risk Assessment',
                fields: [
                    {label: 'Severity', value: (r) => severityTag(String(value(r, 'severity') || '')), tag: true},
                    {label: 'Severity (AI)', value: (r) => severityTag(String(value(r, 'severity_ai') || '')), tag: true},
                    {label: 'Confidence', value: (r) => confidenceTag(value(r, 'confidence')), tag: true},
                    {label: 'Confidence (AI)', value: (r) => confidenceTag(value(r, 'confidence_ai')), tag: true},
                    {label: 'Impact', value: (r) => severityTag(String(value(r, 'impact') || '')), tag: true},
                    {label: 'Impact (AI)', value: (r) => severityTag(String(value(r, 'impact_ai') || '')), tag: true},
                    {label: 'Priority', value: (r) => priorityTag(value(r, 'priority')), tag: true},
                    {label: 'Priority (AI)', value: (r) => priorityTag(value(r, 'priority_ai')), tag: true},
                ],
            },
            {
                key: 'classification',
                title: 'Classification',
                fields: [
                    {label: 'Category', value: (r) => caseCategoryTag(String(value(r, 'category') || '')), tag: true},
                    {label: 'Tags', value: (r) => tags(value(r, 'tags'))},
                    {label: 'Verdict', value: (r) => verdictTag(String(value(r, 'verdict') || '')), tag: true},
                    {label: 'Verdict (AI)', value: (r) => verdictTag(String(value(r, 'verdict_ai') || '')), tag: true},
                ],
            },
            {
                key: 'time',
                title: 'Time',
                fields: [
                    {label: 'Acknowledged Time', value: (r) => formatDateTime(String(value(r, 'acknowledged_time') || ''))},
                    {label: 'Closed Time', value: (r) => formatDateTime(String(value(r, 'closed_time') || ''))},
                ],
            },
            {
                key: 'ownership',
                title: 'Ownership',
                fields: [
                    {label: 'Assignee', value: (r) => stringValue(r, 'assignee_name')},
                ],
            },
            {
                key: 'description',
                title: 'Description',
                fields: [
                    {label: 'Description', value: (r) => stringValue(r, 'description')},
                    {label: 'Summary', value: (r) => stringValue(r, 'summary')},
                    {label: 'Correlation UID', value: (r) => stringValue(r, 'correlation_uid'), mono: true},
                ],
            },
        ],
        tabs: emptyTabs.case,
    },
    alerts: {
        key: 'alerts',
        label: 'Alerts',
        icon: <Siren {...lucideIconProps}/>,
        endpoint: '/alerts/',
        rowKey: 'id',
        searchPlaceholder: 'Alert ID, Title, Rule, Product, Tactic, Source UID',
        filters: [
            {key: 'severity', label: 'Severity', valueType: 'select', width: L160},
            {key: 'confidence', label: 'Confidence', valueType: 'select', width: L160},
            {key: 'impact', label: 'Impact', valueType: 'select', width: L160},
        ],
        advancedFilters: [
            field('alert_id', 'Alert ID', 'text'),
            field('title', 'Title', 'text'),
            field('severity', 'Severity', 'select'),
            field('confidence', 'Confidence', 'select'),
            field('impact', 'Impact', 'select'),
            field('status', 'Status', 'select'),
            field('disposition', 'Disposition', 'select'),
            field('action', 'Action', 'select'),
            field('risk_level', 'Risk Level', 'select'),
            field('product_category', 'Product Category', 'select'),
            field('product_vendor', 'Product Vendor', 'select'),
            field('product_name', 'Product Name', 'select'),
            field('rule_id', 'Rule ID', 'text'),
            field('rule_name', 'Rule Name', 'text'),
            field('correlation_uid', 'Correlation UID', 'text'),
            field('source_uid', 'Source UID', 'text'),
            field('labels', 'Labels', 'tag'),
            field('first_seen_time', 'First Seen', 'date'),
            field('last_seen_time', 'Last Seen', 'date'),
            field('created_at', 'Created Time', 'date'),
        ],
        columns: [
            column('alert_id', 'Alert ID', L132, {required: true, defaultVisible: true, fixed: 'left', openRecord: true, uppercase: true}),
            column('title', 'Title', L400, {required: true, defaultVisible: true, fixed: 'left'}),
            column('severity', 'Severity', L132, {defaultVisible: true, sorter: true, render: (v) => severityTag(String(v || ''))}),
            column('impact', 'Impact', L132, {defaultVisible: true, sorter: true, render: (v) => severityTag(String(v || ''))}),
            column('disposition', 'Disposition', L132, {defaultVisible: true, sorter: true, render: (v) => alertDispositionTag(String(v || ''))}),
            column('risk_level', 'Risk Level', L132, {defaultVisible: true, sorter: true, render: (v) => severityTag(String(v || ''))}),
            column('action', 'Action', L132, {defaultVisible: true, sorter: true, render: (v) => alertActionTag(String(v || ''))}),
            column('confidence', 'Confidence', L132, {defaultVisible: true, sorter: true, render: confidenceTag}),
            column('status', 'Status', L132, {defaultVisible: true, sorter: true, render: (v) => statusTag(String(v || ''))}),
            column('first_seen_time', 'First Seen', L160, {defaultVisible: true, sorter: true, render: date('first_seen_time')}),
            column('last_seen_time', 'Last Seen', L160, {defaultVisible: true, sorter: true, render: date('last_seen_time')}),
            column('product_vendor', 'Product Vendor', L200, {defaultVisible: true, render: (v) => choiceTag(String(v || ''), 'blue')}),
            column('product_name', 'Product Name', L200, {defaultVisible: true, render: (v) => choiceTag(String(v || ''), 'blue')}),
            column('product_feature', 'Product Feature', L200, {defaultVisible: true, render: (v) => choiceTag(String(v || ''), 'blue')}),
            column('labels', 'Labels', L400, {defaultVisible: true, render: (v) => tags(v)}),
            column('case_title', 'Case', L132, {
                defaultVisible: true,
                render: (_v, r) => upperStringValue(r, 'case_readable_id'),
                openResource: {
                    resourceKey: 'cases',
                    rowId: (r) => value(r, 'case_id') as string | number | null | undefined,
                },
            }),
            column('created_at', 'Created Time', L160, {sorter: true, render: date('created_at')}),
            column('updated_at', 'Updated Time', L160, {sorter: true, render: date('updated_at')}),
            column('artifacts_link', 'Artifacts', L132, {
                dataIndex: 'artifact_count',
                defaultVisible: true,
                openRecordTab: 'artifacts',
                render: viewRelatedLabel,
            }),
            column('enrichments_link', 'Enrichments', L132, {
                dataIndex: 'enrichment_count',
                defaultVisible: true,
                openRecordTab: 'enrichments',
                render: viewRelatedLabel,
            }),
            column('rule_id', 'Rule ID', L360),
            column('rule_name', 'Rule Name', L360),
            column('correlation_uid', 'Correlation UID', L360),
            column('source_uid', 'Source UID', L240),
            column('src_url', 'Source URL', L360),
            column('data_sources', 'Data Sources', L400, {render: (v) => tags(v, 'cyan')}),
            column('tactic', 'Tactic', L200),
            column('technique', 'Technique', L200),
            column('sub_technique', 'Sub-technique', L200),
            column('mitigation', 'Mitigation', L400),
            column('desc', 'Description', L400),
            column('status_detail', 'Status Detail', L400),
            column('remediation', 'Remediation', L400),
            column('analytic_name', 'Analytic Name', L240),
            column('analytic_type', 'Analytic Type', L160, {render: (v) => alertAnalyticTypeTag(String(v || ''))}),
            column('analytic_state', 'Analytic State', L160, {render: (v) => choiceTag(String(v || ''), 'green')}),
            column('analytic_desc', 'Analytic Description', L400),
            column('product_category', 'Product Category', L160, {render: (v) => productCategoryTag(String(v || ''))}),
            column('policy_name', 'Policy Name', L240),
            column('policy_type', 'Policy Type', L200, {render: (v) => choiceTag(String(v || ''), 'volcano')}),
            column('policy_desc', 'Policy Description', L400),
        ],
        basicSections: [
            {
                key: 'summary', title: 'Summary', fields: [
                    {label: 'Alert ID', value: (r) => upperStringValue(r, 'alert_id'), mono: true},
                    {label: 'Title', value: (r) => stringValue(r, 'title')},
                ]
            },
            {
                key: 'risk', title: 'Risk Assessment', fields: [
                    {label: 'Severity', value: (r) => severityTag(String(value(r, 'severity') || '')), tag: true},
                    {label: 'Confidence', value: (r) => confidenceTag(value(r, 'confidence')), tag: true},
                    {label: 'Impact', value: (r) => severityTag(String(value(r, 'impact') || '')), tag: true},
                    {label: 'Risk Level', value: (r) => severityTag(String(value(r, 'risk_level') || '')), tag: true},
                ]
            },
            {
                key: 'description', title: 'Description', fields: [
                    {label: 'Labels', value: (r) => tags(value(r, 'labels'))},
                    {label: 'Description', value: (r) => stringValue(r, 'desc')},
                ]
            },
            {
                key: 'correlation', title: 'Correlation', fields: [
                    {label: 'Source UID', value: (r) => stringValue(r, 'source_uid'), mono: true},
                    {label: 'Rule ID', value: (r) => stringValue(r, 'rule_id'), mono: true},
                    {label: 'Rule Name', value: (r) => stringValue(r, 'rule_name')},
                    {label: 'Correlation UID', value: (r) => stringValue(r, 'correlation_uid'), mono: true},
                ]
            },
            {
                key: 'mitre', title: 'MITRE ATT&CK and ATLAS', fields: [
                    {label: 'Tactic', value: (r) => stringValue(r, 'tactic')},
                    {label: 'Technique', value: (r) => stringValue(r, 'technique')},
                    {label: 'Sub-technique', value: (r) => stringValue(r, 'sub_technique')},
                    {label: 'Mitigation', value: (r) => stringValue(r, 'mitigation')},
                ]
            },
            {
                key: 'status', title: 'Status, Action, and Remediation', fields: [
                    {label: 'Status', value: (r) => statusTag(String(value(r, 'status') || '')), tag: true},
                    {label: 'Disposition', value: (r) => alertDispositionTag(String(value(r, 'disposition') || '')), tag: true},
                    {label: 'Action', value: (r) => alertActionTag(String(value(r, 'action') || '')), tag: true},
                    {label: 'Status Detail', value: (r) => stringValue(r, 'status_detail')},
                    {label: 'Remediation', value: (r) => stringValue(r, 'remediation')},
                ]
            },
            {
                key: 'product', title: 'Product and Policy', fields: [
                    {label: 'Product Category', value: (r) => productCategoryTag(String(value(r, 'product_category') || '')), tag: true},
                    {label: 'Product Vendor', value: (r) => choiceTag(String(value(r, 'product_vendor') || ''), 'blue'), tag: true},
                    {label: 'Product Name', value: (r) => choiceTag(String(value(r, 'product_name') || ''), 'blue'), tag: true},
                    {label: 'Product Feature', value: (r) => choiceTag(String(value(r, 'product_feature') || ''), 'blue'), tag: true},
                    {label: 'Policy Name', value: (r) => stringValue(r, 'policy_name')},
                    {label: 'Policy Type', value: (r) => choiceTag(String(value(r, 'policy_type') || '')), tag: true},
                ]
            },
        ],
        basicView: (record, options) => <AlertBasicView record={record} onOpenResource={options?.onOpenResource}/>,
        tabs: emptyTabs.alert,
    },
    artifacts: {
        key: 'artifacts',
        label: 'Artifacts',
        icon: <Fingerprint {...lucideIconProps}/>,
        endpoint: '/artifacts/',
        rowKey: 'id',
        searchPlaceholder: 'Artifact ID, Type, Name, Value, Role',
        filters: [{key: 'type', label: 'Type', valueType: 'select', width: L160}, {key: 'role', label: 'Role', valueType: 'select', width: L160}],
        advancedFilters: [
            field('artifact_id', 'Artifact ID', 'text'),
            field('type', 'Type', 'select'),
            field('role', 'Role', 'select'),
            field('name', 'Name', 'text'),
            field('value', 'Value', 'text'),
            field('created_at', 'Created Time', 'date'),
            field('updated_at', 'Updated Time', 'date'),
        ],
        columns: [
            column('artifact_id', 'Artifact ID', L160, {required: true, defaultVisible: true, fixed: 'left', openRecord: true, uppercase: true}),
            column('name', 'Name', L200, {defaultVisible: true, fixed: 'left', render: (v) => choiceTag(String(v || ''), 'cyan')}),
            column('type', 'Type', L160, {required: true, defaultVisible: true, sorter: true, render: (v) => choiceTag(String(v || ''), 'geekblue')}),
            column('value', 'Value', L400, {required: true, defaultVisible: true}),
            column('role', 'Role', L132, {defaultVisible: true, sorter: true, render: (v) => artifactRoleTag(String(v || ''))}),
            column('alerts_link', 'Alerts', L160, {
                dataIndex: 'alert_count',
                defaultVisible: true,
                openRecordTab: 'alerts',
                render: viewRelatedLabel,
            }),
            column('enrichments_link', 'Enrichments', L160, {
                dataIndex: 'enrichment_count',
                defaultVisible: true,
                openRecordTab: 'enrichments',
                render: viewRelatedLabel,
            }),
            column('created_at', 'Created Time', L160, {defaultVisible: true, sorter: true, render: date('created_at')}),
            column('updated_at', 'Updated Time', L160, {defaultVisible: true, sorter: true, render: date('updated_at')}),
        ],
        basicSections: [
            {
                key: 'summary', title: 'Summary', fields: [
                    {label: 'Artifact ID', value: (r) => upperStringValue(r, 'artifact_id'), mono: true},
                    {label: 'Type', value: (r) => choiceTag(String(value(r, 'type') || ''), 'geekblue'), tag: true},
                    {label: 'Name', value: (r) => choiceTag(String(value(r, 'name') || ''), 'cyan'), tag: true},
                    {label: 'Value', value: (r) => stringValue(r, 'value'), mono: true},
                    {label: 'Role', value: (r) => artifactRoleTag(String(value(r, 'role') || '')), tag: true},
                ]
            },
        ],
        basicView: (record) => <ArtifactBasicView record={record}/>,
        tabs: emptyTabs.artifact,
    },
    enrichments: {
        key: 'enrichments',
        label: 'Enrichments',
        icon: <WandSparkles {...lucideIconProps}/>,
        endpoint: '/enrichments/',
        rowKey: 'id',
        searchPlaceholder: 'Search enrichments by ID, name, provider, value, or UID',
        filters: [{key: 'type', label: 'Type', valueType: 'select', width: L200}, {key: 'provider', label: 'Provider', valueType: 'select', width: L280}],
        advancedFilters: [
            field('enrichment_id', 'Enrichment ID', 'text'),
            field('type', 'Type', 'select'),
            field('provider', 'Provider', 'select'),
            field('name', 'Name', 'text'),
            field('uid', 'UID', 'text'),
            field('value', 'Value', 'text'),
            field('desc', 'Description', 'text'),
            field('created_at', 'Created Time', 'date'),
            field('updated_at', 'Updated Time', 'date'),
        ],
        columns: [
            column('enrichment_id', 'Enrichment ID', L160, {required: true, defaultVisible: true, fixed: 'left', openRecord: true, uppercase: true}),
            column('name', 'Name', L240, {required: true, defaultVisible: true, fixed: 'left'}),
            column('type', 'Type', L200, {defaultVisible: true, sorter: true, render: (v) => choiceTag(String(v || ''), 'magenta')}),
            column('provider', 'Provider', L200, {defaultVisible: true, sorter: true, render: (v) => choiceTag(String(v || ''), 'purple')}),
            column('value', 'Value', L400, {defaultVisible: true}),
            column('linked_object', 'Linked Object', L160, {
                defaultVisible: true,
                render: (_v, r) => upperStringValue(r, 'linked_object'),
                openResource: {
                    resourceKey: linkedObjectResourceKey,
                    rowId: (r) => value(r, 'linked_object_id') as string | number | null | undefined,
                },
            }),
            column('created_at', 'Created Time', L160, {defaultVisible: true, sorter: true, render: date('created_at')}),
            column('updated_at', 'Updated Time', L160, {defaultVisible: true, sorter: true, render: date('updated_at')}),
            column('desc', 'Description', L400),
            column('uid', 'UID', L360),
        ],
        basicSections: [
            {
                key: 'summary', title: 'Summary', fields: [
                    {label: 'Enrichment ID', value: (r) => upperStringValue(r, 'enrichment_id'), mono: true},
                    {label: 'Name', value: (r) => stringValue(r, 'name')},
                    {label: 'Type', value: (r) => choiceTag(String(value(r, 'type') || ''), 'magenta'), tag: true},
                    {label: 'Provider', value: (r) => choiceTag(String(value(r, 'provider') || ''), 'purple'), tag: true},
                    {label: 'UID', value: (r) => stringValue(r, 'uid'), mono: true},
                    {label: 'Value', value: (r) => stringValue(r, 'value'), mono: true},
                    {
                        label: 'Linked Object',
                        value: (r) => upperStringValue(r, 'linked_object'),
                        openResource: {
                            resourceKey: linkedObjectResourceKey,
                            rowId: (r) => value(r, 'linked_object_id') as string | number | null | undefined,
                        },
                    },
                ]
            },
            {
                key: 'description', title: 'Description', fields: [
                    {label: 'Description', value: (r) => stringValue(r, 'desc')},
                ]
            },
        ],
        editableFields: [
            {key: 'uid', type: 'text'},
            {key: 'value', type: 'text'},
            {key: 'desc', type: 'textarea'},
        ],
        basicView: (record, options) => <EnrichmentBasicView record={record} onOpenResource={options?.onOpenResource} fieldController={options?.fieldController}/>,
        tabs: [],
    },
    playbooks: {
        key: 'playbooks',
        label: 'Playbooks',
        icon: <BrainCircuit {...lucideIconProps}/>,
        endpoint: '/playbooks/',
        rowKey: 'id',
        searchPlaceholder: 'Playbook ID, Name, Job ID, Remark',
        filters: [{key: 'job_status', label: 'Status', valueType: 'select', width: L132}],
        advancedFilters: [
            field('playbook_id', 'Playbook ID', 'text'),
            field('job_status', 'Status', 'select'),
            field('name', 'Name', 'text'),
            field('job_id', 'Job ID', 'text'),
            field('user_input', 'User Input', 'text'),
            field('remark', 'Remark', 'text'),
            field('created_at', 'Created Time', 'date'),
            field('updated_at', 'Updated Time', 'date'),
        ],
        columns: [
            column('playbook_id', 'Playbook ID', L160, {required: true, defaultVisible: true, fixed: 'left', openRecord: true, uppercase: true}),
            column('name', 'Name', L360, {required: true, defaultVisible: true, fixed: 'left'}),
            column('job_status', 'Status', L160, {defaultVisible: true, sorter: true, render: playbookJobStatusTag}),
            column('case_title', 'Case', L160, {
                defaultVisible: true,
                render: (_v, r) => upperStringValue(r, 'case_readable_id'),
                openResource: {
                    resourceKey: 'cases',
                    rowId: (r) => value(r, 'case_id') as string | number | null | undefined,
                },
            }),
            column('user_username', 'User', L160, {defaultVisible: true}),
            column('job_id', 'Job ID', L240, {defaultVisible: true}),
            column('created_at', 'Created Time', L160, {defaultVisible: true, sorter: true, render: date('created_at')}),
            column('updated_at', 'Updated Time', L160, {defaultVisible: true, sorter: true, render: date('updated_at')}),
            column('user_input', 'User Input', L400),
            column('remark', 'Remark', L400),
        ],
        basicSections: [
            {
                key: 'summary', title: 'Summary', fields: [
                    {label: 'Playbook ID', value: (r) => upperStringValue(r, 'playbook_id'), mono: true},
                    {label: 'Name', value: (r) => stringValue(r, 'name')},
                    {label: 'Job Status', value: (r) => playbookJobStatusTag(value(r, 'job_status')), tag: true},
                    {label: 'Case', value: playbookCaseLabel, openResource: {resourceKey: 'cases', rowId: (r) => value(r, 'case_id') as string | number | null | undefined}},
                    {label: 'User', value: (r) => stringValue(r, 'user_username')},
                    {label: 'Job ID', value: (r) => stringValue(r, 'job_id'), mono: true},
                    {label: 'Remark', value: (r) => stringValue(r, 'remark')},
                ]
            },
        ],
        basicView: (record, options) => (
            <PlaybookBasicView
                record={record}
                onOpenResource={options?.onOpenResource}
                renderStatus={playbookJobStatusTag}
            />
        ),
        tabs: [],
    },
    knowledge: {
        key: 'knowledge',
        label: 'Knowledge',
        icon: <BookOpenText {...lucideIconProps}/>,
        endpoint: '/knowledge/',
        rowKey: 'id',
        searchPlaceholder: 'Knowledge ID, Title, Body, Source',
        filters: [{key: 'source', label: 'Source', valueType: 'select', width: L132}, {key: 'tags', label: 'Tags', valueType: 'tag', width: L200}],
        advancedFilters: [
            field('knowledge_id', 'Knowledge ID', 'text'),
            field('source', 'Source', 'select'),
            field('tags', 'Tags', 'tag'),
            field('title', 'Title', 'text'),
            field('body', 'Body', 'text'),
            field('expires_at', 'Expires At', 'date'),
            field('created_at', 'Created Time', 'date'),
            field('updated_at', 'Updated Time', 'date'),
        ],
        columns: [
            column('knowledge_id', 'Knowledge ID', L160, {required: true, defaultVisible: true, fixed: 'left', openRecord: true, uppercase: true}),
            column('title', 'Title', L360, {required: true, defaultVisible: true, fixed: 'left'}),
            column('source', 'Source', L132, {defaultVisible: true, sorter: true, render: (v) => knowledgeSourceTag(String(v || ''))}),
            column('case_readable_id', 'Case', L160, {
                defaultVisible: true,
                uppercase: true,
                openResource: {
                    resourceKey: 'cases',
                    rowId: (record) => value(record, 'case') as string | number | null | undefined,
                },
            }),
            column('tags', 'Tags', L400, {defaultVisible: true, render: (v) => tags(v)}),
            column('expires_at', 'Expires At', L160, {defaultVisible: true, sorter: true, render: date('expires_at')}),
            column('created_at', 'Created Time', L160, {defaultVisible: true, sorter: true, render: date('created_at')}),
            column('updated_at', 'Updated Time', L160, {defaultVisible: true, sorter: true, render: date('updated_at')}),
            column('body', 'Body', L400),
        ],
        editableFields: [
            {key: 'title', type: 'text'},
            {key: 'expires_at', type: 'datetime', emptyValue: null},
            {key: 'tags', type: 'tags', emptyValue: []},
            {key: 'body', type: 'markdown'},
        ],
        basicView: (record, options) => (
            <KnowledgeBasicView
                record={record}
                onOpenResource={options?.onOpenResource}
                fieldController={options?.fieldController}
            />
        ),
        basicSections: [
            {
                key: 'summary', title: 'Summary', fields: [
                    {label: 'Knowledge ID', value: (r) => upperStringValue(r, 'knowledge_id'), mono: true},
                    {label: 'Title', value: (r) => stringValue(r, 'title')},
                    {label: 'Source', value: (r) => knowledgeSourceTag(String(value(r, 'source') || '')), tag: true},
                    {label: 'Tags', value: (r) => tags(value(r, 'tags'))},
                    {label: 'Expires At', value: (r) => formatDateTime(String(value(r, 'expires_at') || ''))},
                    {label: 'Body', value: (r) => stringValue(r, 'body')},
                ]
            },
        ],
        tabs: [],
    },
    users: {
        key: 'users',
        label: 'Users',
        icon: <UserOutlined/>,
        endpoint: '/auth/users/',
        rowKey: 'id',
        searchPlaceholder: 'Username, Email, Name, Phone',
        filters: [
            {key: 'role', label: 'Role', options: [{label: 'Admin', value: 'admin'}, {label: 'User', value: 'user'}, {label: 'Viewer', value: 'viewer'}], width: L132},
            {key: 'auth_type', label: 'Auth Type', options: [{label: 'Local', value: 'local'}, {label: 'LDAP', value: 'ldap'}], width: L132},
            {key: 'is_active', label: 'Status', options: [{label: 'Active', value: 'true'}, {label: 'Disabled', value: 'false'}], width: L132},
        ],
        advancedFilters: [
            field('username', 'Username', 'text'),
            field('email', 'Email', 'text'),
            field('first_name', 'First Name', 'text'),
            field('last_name', 'Last Name', 'text'),
            field('mobile_phone', 'Mobile Phone', 'text'),
            field('auth_type', 'Auth Type', 'select'),
            field('is_active', 'Status', 'select'),
            field('date_joined', 'Date Joined', 'date'),
            field('last_login', 'Last Login', 'date'),
        ],
        columns: [
            column('username', 'Username', L160, {required: true, defaultVisible: true, openRecord: true}),
            column('avatar_url', 'Avatar', L80, {
                defaultVisible: true,
                render: (_v, r) => <UserAvatar username={String(value(r, 'username') || '')} avatarUrl={String(value(r, 'avatar_url') || '')} size={32}/>
            }),
            column('role', 'Role', L120, {defaultVisible: true, render: userRoleTag}),
            column('auth_type', 'Auth Type', L120, {defaultVisible: true, sorter: true, render: authTypeTag}),
            column('is_active', 'Status', L120, {defaultVisible: true, sorter: true, render: activeStatusTag}),
            column('email', 'Email', L240, {defaultVisible: true}),
            column('first_name', 'First Name', L120),
            column('last_name', 'Last Name', L120),
            column('full_name', 'Full Name', L200, {
                defaultVisible: true,
                render: (_v, r) => `${stringValue(r, 'first_name')} ${stringValue(r, 'last_name')}`.replaceAll('—', '').trim() || '—'
            }),
            column('mobile_phone', 'Mobile Phone', L240, {defaultVisible: true}),
            column('last_login', 'Last Login', L160, {defaultVisible: true, sorter: true, render: date('last_login')}),
            column('date_joined', 'Date Joined', L160, {defaultVisible: true, sorter: true, render: date('date_joined')}),
        ],
        basicSections: [
            {
                key: 'identity', title: 'Identity', fields: [
                    {label: 'Username', value: (r) => stringValue(r, 'username')},
                    {label: 'Email', value: (r) => stringValue(r, 'email')},
                    {label: 'Full Name', value: (r) => `${stringValue(r, 'first_name')} ${stringValue(r, 'last_name')}`.replaceAll('—', '').trim() || '—'},
                    {label: 'Mobile Phone', value: (r) => stringValue(r, 'mobile_phone')},
                    {label: 'Avatar', value: (r) => <UserAvatar username={String(value(r, 'username') || '')} avatarUrl={String(value(r, 'avatar_url') || '')} size={40}/>},
                ]
            },
            {
                key: 'access', title: 'Access', fields: [
                    {label: 'Role', value: (r) => userRoleTag(value(r, 'role')), tag: true},
                    {label: 'Auth Type', value: (r) => authTypeTag(value(r, 'auth_type')), tag: true},
                    {label: 'Status', value: (r) => activeStatusTag(value(r, 'is_active')), tag: true},
                ]
            },
        ],
        tabs: [],
    },
    'llm-providers': {
        key: 'llm-providers',
        label: 'LLM Providers',
        icon: <ApiOutlined/>,
        endpoint: '/settings/llm-providers/',
        rowKey: 'id',
        searchPlaceholder: 'Name, Base Url, Model',
        filters: [
            {key: 'enabled', label: 'Enabled', valueType: 'select', options: [{label: 'Enabled', value: 'true'}, {label: 'Disabled', value: 'false'}], width: L132},
            {key: 'tags', label: 'Tags', valueType: 'tag', options: llmTagOptions, width: L480},
        ],
        advancedFilters: [
            field('name', 'Name', 'text'),
            field('base_url', 'Base URL', 'text'),
            field('model', 'Model', 'text'),
            {key: 'enabled', label: 'Enabled', valueType: 'select', options: [{label: 'Enabled', value: 'true'}, {label: 'Disabled', value: 'false'}]},
            field('priority', 'Priority', 'number'),
        ],
        columns: [
            column('name', 'Name', L160, {required: true, defaultVisible: true, openRecord: true, sorter: true}),
            column('base_url', 'Base URL', L360, {defaultVisible: true, sorter: true}),
            column('model', 'Model', L240, {defaultVisible: true, sorter: true}),
            column('tags', 'Tags', L360, {defaultVisible: true, render: llmTags}),
            column('enabled', 'Enabled', L96, {defaultVisible: true, sorter: true, render: llmProviderStatusTag}),
            column('priority', 'Priority', L96, {defaultVisible: true, sorter: true}),
        ],
        basicSections: [],
        tabs: [],
    },
}

export function getResourceConfig(key: string): ResourceConfig<RecordRow> {
    const config = resourceConfigs[key]
    if (!config) throw new Error(`Unknown resource config: ${key}`)
    return config
}
