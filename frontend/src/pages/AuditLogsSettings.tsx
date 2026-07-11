import {useMemo, useState} from 'react'
import type {Dayjs} from 'dayjs'
import dayjs from 'dayjs'
import {Button, DatePicker, Descriptions, Space, Tooltip, Typography} from 'antd'
import {ExportOutlined} from '@ant-design/icons'
import DataTable from '../components/DataTable'
import JsonViewer from '../components/JsonViewer'
import RecordDetailModal from '../components/RecordDetailModal'
import client from '../api/client'
import {getResourceConfig} from '../config/resources'
import type {OpenResourceOptions, ResourceColumn, ResourceConfig, ResourceFilterConfig, AdvancedFilterFieldConfig} from '../types/records'
import {message} from '../utils/appMessage'
import {choiceTag, emptyValue, formatDateTime} from '../utils/recordDisplay'
import {monoTextStyle} from '../utils/typography'

const { RangePicker } = DatePicker

type RecordRow = Record<string, unknown>
type RangeValue = [Dayjs, Dayjs] | null

const actionColors: Record<string, string> = {
  create: 'green',
  update: 'blue',
  delete: 'red',
  linked: 'cyan',
  unlinked: 'orange',
  deleted: 'red',
  reveal: 'purple',
  test: 'gold',
}

const actionOptions = [
  'create',
  'update',
  'delete',
  'linked',
  'unlinked',
  'deleted',
  'reveal',
  'test',
].map((value) => ({ label: value, value }))

const resourceTypeOptions = [
  { label: 'Case', value: 'case' },
  { label: 'Alert', value: 'alert' },
  { label: 'Artifact', value: 'artifact' },
  { label: 'Enrichment', value: 'enrichment' },
  { label: 'Playbook', value: 'playbook' },
  { label: 'Knowledge', value: 'knowledge' },
  { label: 'User', value: 'user' },
  { label: 'LLM Provider', value: 'llmproviderconfig' },
  { label: 'AlienVault OTX Settings', value: 'threatintelalienvaultotxconfig' },
  { label: 'OpenCTI Settings', value: 'threatintelopencticonfig' },
  { label: 'Splunk Settings', value: 'siemsplunkconfig' },
  { label: 'ELK Settings', value: 'siemelkconfig' },
  { label: 'LDAP Settings', value: 'ldapconfig' },
  { label: 'Runtime Settings', value: 'runtimeconfig' },
]

const linkableResourceKeys = new Set(['cases', 'alerts', 'artifacts', 'enrichments', 'playbooks', 'knowledge', 'users', 'llm-providers'])

const endpoint = '/settings/audit-logs/'
const searchPlaceholder = 'Audit ID, actor, action, resource, object ID, field, changes, metadata'

const filters: ResourceFilterConfig[] = [
  { key: 'action', label: 'Action', valueType: 'select', options: actionOptions, width: 132 },
  { key: 'actor', label: 'Actor', valueType: 'user', options: [{ label: 'system', value: 'system' }], width: 180 },
  { key: 'resource_type', label: 'Resource Type', valueType: 'select', options: resourceTypeOptions, width: 200 },
]

const advancedFilters: AdvancedFilterFieldConfig[] = [
  { key: 'action', label: 'Action', valueType: 'select', options: actionOptions },
  { key: 'actor', label: 'Actor', valueType: 'user', options: [{ label: 'system', value: 'system' }] },
  { key: 'resource_type', label: 'Resource Type', valueType: 'select', options: resourceTypeOptions },
  { key: 'object_id', label: 'Object ID', valueType: 'text' },
  { key: 'field', label: 'Field / Relation', valueType: 'text' },
  { key: 'relation', label: 'Relation', valueType: 'text' },
  { key: 'related_resource', label: 'Related Resource', valueType: 'text' },
  { key: 'related_id', label: 'Related ID', valueType: 'text' },
  { key: 'related_label', label: 'Related Label', valueType: 'text' },
  { key: 'changes', label: 'Changes JSON', valueType: 'text' },
  { key: 'metadata', label: 'Metadata JSON', valueType: 'text' },
  { key: 'created_at', label: 'Created Time', valueType: 'date' },
]

const value = (record: RecordRow, key: string) => record[key]
const textValue = (record: RecordRow, key: string) => emptyValue(value(record, key))
const actorDisplay = (record: RecordRow) => {
  const actorName = String(value(record, 'actor_name') || '')
  const actor = String(value(record, 'actor') || '')
  return actorName || actor || 'system'
}
const actionTag = (rawValue: unknown) => {
  const action = String(rawValue || '')
  return choiceTag(action, actionColors[action] || 'default')
}
const date = (field: string) => (_: unknown, record: RecordRow) => formatDateTime(String(value(record, field) || ''))
const mono = (content: unknown) => (
  <Typography.Text copyable={Boolean(content)} style={monoTextStyle}>
    {emptyValue(content)}
  </Typography.Text>
)
const canOpenResource = (resourceKey: unknown, rowId: unknown, action?: unknown) => (
  typeof resourceKey === 'string'
  && linkableResourceKeys.has(resourceKey)
  && rowId !== null
  && rowId !== undefined
  && rowId !== ''
  && !['delete', 'deleted'].includes(String(action || ''))
)

function AuditLogBasicView({
  record,
  onOpenResource,
}: {
  record: RecordRow
  onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
}) {
  const objectResourceKey = String(value(record, 'resource_key') || '')
  const objectId = value(record, 'object_id') as string | number | null | undefined
  const relatedResourceKey = String(value(record, 'related_resource') || '')
  const relatedId = value(record, 'related_id') as string | number | null | undefined
  const action = value(record, 'action')

  return (
    <div style={{ padding: '20px 20px 16px', overflow: 'auto', height: '100%', boxSizing: 'border-box' }}>
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Descriptions column={2} size="small" bordered>
          <Descriptions.Item label="Audit ID">{mono(value(record, 'readable_id'))}</Descriptions.Item>
          <Descriptions.Item label="Time">{formatDateTime(String(value(record, 'created_at') || ''))}</Descriptions.Item>
          <Descriptions.Item label="Action">{actionTag(action)}</Descriptions.Item>
          <Descriptions.Item label="Actor">{actorDisplay(record)}</Descriptions.Item>
          <Descriptions.Item label="Resource Type">{textValue(record, 'resource_label')}</Descriptions.Item>
          <Descriptions.Item label="Object ID">
            {canOpenResource(objectResourceKey, objectId, action) ? (
              <Button type="link" size="small" style={{ padding: 0, height: 'auto', ...monoTextStyle }} onClick={() => onOpenResource?.(objectResourceKey, objectId!)}>
                {textValue(record, 'object_id')}
              </Button>
            ) : mono(value(record, 'object_id'))}
          </Descriptions.Item>
          <Descriptions.Item label="Field / Relation">{textValue(record, 'field_summary')}</Descriptions.Item>
          <Descriptions.Item label="Related Resource">{textValue(record, 'related_resource')}</Descriptions.Item>
          <Descriptions.Item label="Related Record">
            {canOpenResource(relatedResourceKey, relatedId, action) ? (
              <Button type="link" size="small" style={{ padding: 0, height: 'auto' }} onClick={() => onOpenResource?.(relatedResourceKey, relatedId!)}>
                {textValue(record, 'related_label') !== '—' ? textValue(record, 'related_label') : textValue(record, 'related_id')}
              </Button>
            ) : textValue(record, 'related_label') !== '—' ? textValue(record, 'related_label') : mono(value(record, 'related_id'))}
          </Descriptions.Item>
          <Descriptions.Item label="Summary" span={2}>{textValue(record, 'summary')}</Descriptions.Item>
        </Descriptions>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 16, alignItems: 'start' }}>
          <div style={{ minWidth: 0 }}>
            <Typography.Title level={5}>Changes</Typography.Title>
            <JsonViewer value={value(record, 'display_changes') || value(record, 'changes')} maxHeight="none" />
          </div>
          <div style={{ minWidth: 0 }}>
            <Typography.Title level={5}>Metadata</Typography.Title>
            <JsonViewer value={value(record, 'metadata')} maxHeight="none" />
          </div>
        </div>
      </Space>
    </div>
  )
}

function exportFilename(disposition: string | undefined) {
  const match = disposition?.match(/filename="?([^"]+)"?/)
  return match?.[1] || `audit-logs-${dayjs().format('YYYYMMDD-HHmmss')}.csv`
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export default function AuditLogsSettings() {
  const [createdRange, setCreatedRange] = useState<RangeValue>(() => [dayjs().subtract(24, 'hour'), dayjs()])
  const [selectedAuditLogId, setSelectedAuditLogId] = useState<string | number | null>(null)
  const [exporting, setExporting] = useState(false)
  const [relatedDetail, setRelatedDetail] = useState<{
    config: ResourceConfig
    rowId: string | number
  } | null>(null)

  const baseParams = useMemo(() => {
    if (!createdRange?.[0] && !createdRange?.[1]) return {}
    return {
      created_after: createdRange?.[0]?.toISOString(),
      created_before: createdRange?.[1]?.toISOString(),
    }
  }, [createdRange])

  const columns = useMemo<ResourceColumn<RecordRow>[]>(() => [
    { key: 'readable_id', title: 'Audit ID', dataIndex: 'readable_id', width: 150, required: true, defaultVisible: true, fixed: 'left', openRecord: true, uppercase: true },
    { key: 'created_at', title: 'Time', dataIndex: 'created_at', width: 180, defaultVisible: true, sorter: true, render: date('created_at') },
    { key: 'action', title: 'Action', dataIndex: 'action', width: 120, defaultVisible: true, sorter: true, render: actionTag },
    { key: 'actor_name', title: 'Actor', dataIndex: 'actor_name', width: 180, defaultVisible: true, sorter: true, render: (_v, record) => actorDisplay(record) },
    { key: 'resource_label', title: 'Resource Type', dataIndex: 'resource_label', width: 180, defaultVisible: true },
    {
      key: 'object_id',
      title: 'Object ID',
      dataIndex: 'object_id',
      width: 360,
      defaultVisible: true,
      sorter: true,
      render: (raw, record) => canOpenResource(value(record, 'resource_key'), raw, value(record, 'action')) ? emptyValue(raw) : mono(raw),
      openResource: {
        resourceKey: (record) => canOpenResource(value(record, 'resource_key'), value(record, 'object_id'), value(record, 'action')) ? String(value(record, 'resource_key')) : null,
        rowId: (record) => value(record, 'object_id') as string | number | null | undefined,
      },
    },
    { key: 'field_summary', title: 'Field / Relation', dataIndex: 'field_summary', width: 180, defaultVisible: true },
    {
      key: 'related_label',
      title: 'Related Record',
      dataIndex: 'related_label',
      width: 240,
      defaultVisible: true,
      render: (_raw, record) => textValue(record, 'related_label') !== '—' ? textValue(record, 'related_label') : textValue(record, 'related_id'),
      openResource: {
        resourceKey: (record) => canOpenResource(value(record, 'related_resource'), value(record, 'related_id'), value(record, 'action')) ? String(value(record, 'related_resource')) : null,
        rowId: (record) => value(record, 'related_id') as string | number | null | undefined,
      },
    },
    { key: 'summary', title: 'Summary', dataIndex: 'summary', width: 520, defaultVisible: true },
    { key: 'changes_json', title: 'Changes JSON', dataIndex: 'changes_json', width: 480 },
    { key: 'metadata_json', title: 'Metadata JSON', dataIndex: 'metadata_json', width: 480 },
  ], [])

  const detailConfig = useMemo<ResourceConfig<RecordRow>>(() => ({
    key: 'audit-logs',
    label: 'Audit Logs',
    endpoint,
    rowKey: 'id',
    searchPlaceholder,
    columns,
    filters,
    advancedFilters,
    basicView: (record, options) => <AuditLogBasicView record={record} onOpenResource={options?.onOpenResource} />,
    showShare: false,
    showActivity: false,
    basicSections: [],
    tabs: [],
  }), [columns])

  const openRelatedDetail = (resourceKey: string, rowId: string | number) => {
    if (!linkableResourceKeys.has(resourceKey)) return
    setRelatedDetail({ config: getResourceConfig(resourceKey), rowId })
  }

  const exportCsv = async (params: Record<string, string | number | boolean | undefined>) => {
    const exportParams = { ...params }
    delete exportParams.page
    delete exportParams.page_size
    setExporting(true)
    try {
      const response = await client.get(`${endpoint}export/`, {
        params: exportParams,
        responseType: 'blob',
      })
      downloadBlob(response.data, exportFilename(response.headers['content-disposition']))
      message.success('Audit logs exported')
    } catch {
      message.error('Failed to export audit logs')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0 }}>
      <DataTable
        endpoint={endpoint}
        tableKey="audit-logs"
        savedFiltersKey="audit-logs"
        rowKey="id"
        columns={columns}
        filters={filters}
        advancedFilters={advancedFilters}
        searchPlaceholder={searchPlaceholder}
        baseParams={baseParams}
        filterActions={(
          <RangePicker
            showTime
            allowClear
            value={createdRange}
            onChange={(next) => setCreatedRange(next as RangeValue)}
            style={{ width: 360 }}
          />
        )}
        readOnly
        fillParent
        onRowClick={(record) => setSelectedAuditLogId(value(record, 'id') as string | number)}
        onOpenResource={openRelatedDetail}
        actions={({ params }) => (
          <Tooltip title="Export CSV">
            <Button icon={<ExportOutlined />} loading={exporting} onClick={() => exportCsv(params)} />
          </Tooltip>
        )}
      />
      <RecordDetailModal
        config={detailConfig}
        rowId={selectedAuditLogId}
        open={selectedAuditLogId !== null}
        onClose={() => setSelectedAuditLogId(null)}
        onOpenResource={openRelatedDetail}
      />
      {relatedDetail && (
        <RecordDetailModal
          config={relatedDetail.config}
          rowId={relatedDetail.rowId}
          open
          onOpenResource={openRelatedDetail}
          onClose={() => setRelatedDetail(null)}
        />
      )}
    </div>
  )
}
