import {type CSSProperties, useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {Alert, Button, Empty, Input, Modal, Space, Table, Tag, theme, Tooltip, Typography} from 'antd'
import {message} from '../utils/appMessage'
import {ReloadOutlined, SearchOutlined, ThunderboltOutlined} from '@ant-design/icons'
import type {ColumnsType} from 'antd/es/table'
import client from '../api/client'
import OverflowTags from './OverflowTags'
import {comfortableTagProps} from '../utils/tagStyles'

type RecordRow = Record<string, unknown>

interface PlaybookDefinition {
  name: string
  description: string
  tags: string[]
}

interface CasePlaybookActionProps {
  record: RecordRow
  disabled?: boolean
  buttonStyle?: CSSProperties
  refreshRecord: () => void
}

interface CasePlaybookRunModalProps {
  open: boolean
  caseId: string
  onClose: () => void
  onSubmitted?: () => void
}

const PLAYBOOK_TAG_COLORS: Record<string, string> = {
  System: 'gold',
  LLM: 'purple',
  Case: 'green',
  Knowledge: 'magenta',
  CMDB: 'geekblue',
  'Threat Intel': 'volcano',
  Enrichment: 'cyan',
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function apiErrorMessage(error: unknown, fallback: string) {
  const data = (error as { response?: { data?: unknown } }).response?.data
  if (typeof data === 'string') return data
  if (isObjectRecord(data) && typeof data.detail === 'string') return data.detail
  return fallback
}

function normalizeTags(tags: unknown) {
  return Array.isArray(tags)
    ? tags.map((tag) => String(tag).trim()).filter(Boolean)
    : []
}

function PlaybookTags({ tags }: { tags: unknown }) {
  return <OverflowTags items={normalizeTags(tags)} getColor={(tag) => PLAYBOOK_TAG_COLORS[tag] || 'blue'} />
}

function CasePlaybookRunModal({ open, caseId, onClose, onSubmitted }: CasePlaybookRunModalProps) {
  const { token } = theme.useToken()
  const [definitions, setDefinitions] = useState<PlaybookDefinition[]>([])
  const [selectedName, setSelectedName] = useState('')
  const [userInput, setUserInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [loadError, setLoadError] = useState('')
  const requestIdRef = useRef(0)

  const selectedDefinition = useMemo(
    () => definitions.find((definition) => definition.name === selectedName) || null,
    [definitions, selectedName],
  )
  const tagFilters = useMemo(() => {
    const tags = new Set<string>()
    definitions.forEach((definition) => {
      normalizeTags(definition.tags).forEach((tag) => tags.add(tag))
    })
    return [...tags].sort((left, right) => left.localeCompare(right)).map((tag) => ({
      text: <Tag {...comfortableTagProps} color={PLAYBOOK_TAG_COLORS[tag] || 'blue'} style={{ marginInlineEnd: 0 }}>{tag}</Tag>,
      value: tag,
    }))
  }, [definitions])

  const loadDefinitions = useCallback(() => {
    const requestId = requestIdRef.current + 1
    requestIdRef.current = requestId
    setLoading(true)
    setLoadError('')

    client.get<PlaybookDefinition[]>('/playbooks/definitions/')
      .then(({ data }) => {
        if (requestId !== requestIdRef.current) return
        setDefinitions(data)
        setSelectedName((current) => (
          current && data.some((definition) => definition.name === current)
            ? current
            : data[0]?.name || ''
        ))
      })
      .catch((error) => {
        if (requestId !== requestIdRef.current) return
        setDefinitions([])
        setSelectedName('')
        setLoadError(apiErrorMessage(error, 'Failed to load playbooks'))
      })
      .finally(() => {
        if (requestId === requestIdRef.current) setLoading(false)
      })
  }, [])

  useEffect(() => {
    if (!open) return
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadDefinitions()

    return () => {
      requestIdRef.current += 1
    }
  }, [loadDefinitions, open])

  const columns = useMemo<ColumnsType<PlaybookDefinition>>(() => [
    {
      title: 'Playbook',
      dataIndex: 'name',
      width: 280,
      filterDropdown: ({ selectedKeys, setSelectedKeys, confirm, clearFilters }) => (
        <div style={{ padding: 8, width: 280 }} onKeyDown={(event) => event.stopPropagation()}>
          <Input.Search
            autoFocus
            allowClear
            placeholder="Search playbooks"
            value={String(selectedKeys[0] || '')}
            onChange={(event) => setSelectedKeys(event.target.value ? [event.target.value] : [])}
            onSearch={() => confirm({ closeDropdown: true })}
          />
          <Space style={{ marginTop: 8, justifyContent: 'flex-end', width: '100%' }}>
            <Button size="small" onClick={() => {
              clearFilters?.({ confirm: true, closeDropdown: true })
            }}>
              Reset
            </Button>
            <Button type="primary" size="small" icon={<SearchOutlined />} onClick={() => confirm({ closeDropdown: true })}>
              Search
            </Button>
          </Space>
        </div>
      ),
      filterIcon: (filtered) => <SearchOutlined style={{ color: filtered ? '#1677ff' : undefined }} />,
      onFilter: (filterValue, definition) => {
        const keyword = String(filterValue).trim().toLowerCase()
        if (!keyword) return true
        return [
          definition.name,
          definition.description,
          ...normalizeTags(definition.tags),
        ].some((value) => value.toLowerCase().includes(keyword))
      },
      render: (name: string) => <Typography.Text strong>{name}</Typography.Text>,
    },
    {
      title: 'Tags',
      dataIndex: 'tags',
      width: 300,
      filters: tagFilters,
      filterSearch: true,
      onFilter: (filterValue, definition) => normalizeTags(definition.tags).includes(String(filterValue)),
      render: (tags: string[]) => <PlaybookTags tags={tags} />,
    },
  ], [tagFilters])

  const submit = async () => {
    if (!selectedDefinition || !caseId) return
    setSubmitting(true)
    try {
      await client.post('/playbooks/run/', {
        name: selectedDefinition.name,
        case: caseId,
        user_input: userInput,
      })
      message.success('Playbook submitted')
      onClose()
      onSubmitted?.()
    } catch (error) {
      message.error(apiErrorMessage(error, 'Failed to submit playbook'))
    } finally {
      setSubmitting(false)
    }
  }

  const runDisabled = loading || Boolean(loadError) || !selectedDefinition || !caseId

  return (
    <Modal
      title={(
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
          <ThunderboltOutlined style={{ color: token.colorPrimary }} />
          <span>Run Playbook</span>
        </span>
      )}
      open={open}
      onCancel={onClose}
      width="min(1280px, calc(100vw - 64px))"
      destroyOnHidden
      styles={{
        container: { background: token.colorBgContainer, border: `1px solid ${token.colorBorder}` },
        header: { background: token.colorBgContainer },
        body: { background: token.colorBgContainer },
        footer: { background: token.colorBgContainer },
      }}
      footer={[
        <Button key="cancel" onClick={onClose} disabled={submitting}>
          Cancel
        </Button>,
        <Button key="run" type="primary" icon={<ThunderboltOutlined />} loading={submitting} disabled={runDisabled} onClick={submit}>
          Run
        </Button>,
      ]}
    >
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 3fr) minmax(360px, 2fr)', gap: 20, minHeight: 600 }}>
        <div style={{ minWidth: 0 }}>
          {loadError && (
            <Alert
              type="error"
              showIcon
              title={loadError}
              style={{ marginBottom: 12 }}
              action={<Button size="small" icon={<ReloadOutlined />} onClick={loadDefinitions}>Retry</Button>}
            />
          )}
          <Table<PlaybookDefinition>
            size="small"
            rowKey="name"
            columns={columns}
            dataSource={definitions}
            loading={loading}
            pagination={false}
            rowSelection={{
              type: 'radio',
              selectedRowKeys: selectedName ? [selectedName] : [],
              onChange: (keys) => setSelectedName(String(keys[0] || '')),
            }}
            onRow={(definition) => ({
              onClick: () => setSelectedName(definition.name),
              style: { cursor: 'pointer' },
            })}
            locale={{ emptyText: loading ? <span /> : <Empty description="No playbooks found" /> }}
            scroll={{ y: 528 }}
          />
        </div>
        <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {selectedDefinition ? (
            <>
              <div>
                <Typography.Title level={5} style={{ marginTop: 0 }}>{selectedDefinition.name}</Typography.Title>
                <PlaybookTags tags={selectedDefinition.tags} />
              </div>
              <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
                {selectedDefinition.description || 'No description.'}
              </Typography.Paragraph>
              <div style={{ marginTop: 'auto' }}>
                <Typography.Text strong>User input</Typography.Text>
                <Input.TextArea
                  value={userInput}
                  onChange={(event) => setUserInput(event.target.value)}
                  placeholder="Optional input for this playbook"
                  autoSize={{ minRows: 6, maxRows: 10 }}
                  disabled={submitting}
                  style={{ marginTop: 8 }}
                />
              </div>
            </>
          ) : (
            <Empty description={loading ? 'Loading playbooks' : 'Select a playbook'} />
          )}
        </div>
      </div>
    </Modal>
  )
}

export default function CasePlaybookAction({ record, disabled, buttonStyle, refreshRecord }: CasePlaybookActionProps) {
  const [open, setOpen] = useState(false)
  const caseId = typeof record.id === 'string' || typeof record.id === 'number' ? String(record.id) : ''
  const actionDisabled = disabled || !caseId

  return (
    <>
      <Tooltip title="Run Playbook">
        <Button
          type="text"
          size="large"
          style={buttonStyle}
          icon={<ThunderboltOutlined />}
          disabled={actionDisabled}
          onClick={() => setOpen(true)}
        />
      </Tooltip>
      {open && (
        <CasePlaybookRunModal
          open={open}
          caseId={caseId}
          onClose={() => setOpen(false)}
          onSubmitted={refreshRecord}
        />
      )}
    </>
  )
}
