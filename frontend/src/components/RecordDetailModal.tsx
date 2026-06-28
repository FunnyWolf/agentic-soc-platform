import {useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {Button, Divider, Empty, message, Modal, Spin, theme, Tooltip} from 'antd'
import {CloseOutlined, FileTextOutlined, HistoryOutlined, MenuFoldOutlined, MenuUnfoldOutlined, MessageOutlined, ReloadOutlined, ShareAltOutlined} from '@ant-design/icons'
import client from '../api/client'
import type {FieldEditingController, OpenResourceOptions, ResourceConfig} from '../types/records'
import AuditTimeline from './AuditTimeline'
import DetailDraftActionBar from './DetailDraftActionBar'
import DiscussionThread from './DiscussionThread'
import RecordBasicView from './RecordBasicView'
import RecordTimestampSummary from './RecordTimestampSummary'
import {editableValuesEqual, normalizeEditableDraftValue, normalizeEditableSaveValue} from './fieldEditing'
import {typography} from '../utils/typography'
import {buildRecordShareUrl} from '../utils/recordShare'

interface RecordDetailModalProps {
  config: ResourceConfig
  rowId: string | number | null
  open: boolean
  initialTabKey?: string
  onClose: () => void
  onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
  onChanged?: () => void
}

const contentTypeMap: Record<string, string> = {
  cases: 'case',
  alerts: 'alert',
  artifacts: 'artifact',
  enrichments: 'enrichment',
  playbooks: 'playbook',
  knowledge: 'knowledge',
  users: 'user',
}

const headerActionButtonStyle = { width: 40, height: 40 }
type ActivityDrawerKey = 'comments' | 'log'

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function apiStatus(error: unknown) {
  return (error as { response?: { status?: number } }).response?.status
}

function apiData(error: unknown) {
  return (error as { response?: { data?: unknown } }).response?.data
}

function errorText(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item)).join(' ')
  if (typeof value === 'string') return value
  if (isObjectRecord(value)) return JSON.stringify(value)
  return String(value)
}

function apiErrorMessage(data: unknown) {
  if (typeof data === 'string') return data
  if (isObjectRecord(data) && typeof data.detail === 'string') return data.detail
  return 'Failed to update record'
}

function extractFieldErrors(data: unknown, editableFieldKeys: Set<string>) {
  if (!isObjectRecord(data)) return {}
  return Object.fromEntries(
    Object.entries(data)
      .filter(([key]) => editableFieldKeys.has(key))
      .map(([key, value]) => [key, errorText(value)]),
  )
}

function removeFieldKey<T>(values: Record<string, T>, key: string) {
  if (!Object.hasOwn(values, key)) return values
  const next = { ...values }
  delete next[key]
  return next
}

export default function RecordDetailModal({ config, rowId, open, initialTabKey, onClose, onOpenResource, onChanged }: RecordDetailModalProps) {
  const { token } = theme.useToken()
  const dividerBorder = `1px solid ${token.colorBorderSecondary}`
  const [record, setRecord] = useState<Record<string, unknown> | null>(null)
  const [loadedRowId, setLoadedRowId] = useState<string | number | null>(null)
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [editDraft, setEditDraft] = useState<Record<string, unknown>>({})
  const [activeFieldKey, setActiveFieldKey] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [activeTab, setActiveTab] = useState('basic')
  const [railExpanded, setRailExpanded] = useState(false)
  const [activityDrawer, setActivityDrawer] = useState<ActivityDrawerKey | null>(null)
  const [changedSinceOpen, setChangedSinceOpen] = useState(false)
  const requestIdRef = useRef(0)

  const loadedCurrentRecord = loadedRowId === rowId ? record : null
  const editableFields = useMemo(() => config.editableFields || [], [config.editableFields])
  const editableFieldMap = useMemo(
    () => new Map(editableFields.map((field) => [field.key, field])),
    [editableFields],
  )

  const dirtyFieldKeys = useMemo(() => {
    if (!loadedCurrentRecord) return []
    return editableFields
      .filter((field) => (
        Object.hasOwn(editDraft, field.key)
        && !editableValuesEqual(field, loadedCurrentRecord[field.key], editDraft[field.key])
      ))
      .map((field) => field.key)
  }, [editDraft, editableFields, loadedCurrentRecord])

  const dirtyFieldSet = useMemo(() => new Set(dirtyFieldKeys), [dirtyFieldKeys])
  const hasDirtyFields = dirtyFieldKeys.length > 0

  const clearFieldEditing = useCallback(() => {
    setEditDraft({})
    setActiveFieldKey(null)
    setFieldErrors({})
  }, [])

  const loadRecord = useCallback((nextRowId: string | number, options: { reset: boolean }) => {
    const requestId = requestIdRef.current + 1
    requestIdRef.current = requestId
    if (options.reset) {
      setRecord(null)
      setLoadedRowId(null)
      setLoading(true)
      clearFieldEditing()
    } else {
      setRefreshing(true)
    }

    client.get(`${config.endpoint}${nextRowId}/`)
      .then(({ data }) => {
        if (requestId !== requestIdRef.current) return
        setRecord(data)
        setLoadedRowId(nextRowId)
        clearFieldEditing()
      })
      .catch((error) => {
        if (requestId !== requestIdRef.current) return
        const status = apiStatus(error)
        if (status === 404) {
          clearFieldEditing()
          message.warning('Record not found or has been deleted')
          onClose()
          return
        }
        if (status === 403) {
          clearFieldEditing()
          message.error('You do not have permission to view this record')
          onClose()
          return
        }
        if (options.reset) {
          setRecord(null)
          setLoadedRowId(null)
        }
        message.error(options.reset ? 'Failed to load record detail' : 'Failed to refresh record')
      })
      .finally(() => {
        if (requestId === requestIdRef.current) {
          setLoading(false)
          setRefreshing(false)
        }
      })
  }, [clearFieldEditing, config.endpoint, onClose])

  const requestClose = useCallback(() => {
    if (saving) {
      message.warning('Please wait for save to finish')
      return
    }
    clearFieldEditing()
    if (changedSinceOpen) {
      setChangedSinceOpen(false)
      onChanged?.()
    }
    onClose()
  }, [changedSinceOpen, clearFieldEditing, onChanged, onClose, saving])

  const requestRefresh = useCallback(() => {
    if (rowId === null || rowId === undefined) return
    clearFieldEditing()
    loadRecord(rowId, { reset: false })
  }, [clearFieldEditing, loadRecord, rowId])

  const markChanged = useCallback(() => {
    setChangedSinceOpen(true)
  }, [])

  const refreshAfterMutation = useCallback(() => {
    markChanged()
    requestRefresh()
  }, [markChanged, requestRefresh])

  const requestTabChange = useCallback((nextTab: string) => {
    if (nextTab === activeTab) return
    if (saving) {
      message.warning('Please wait for save to finish')
      return
    }
    setActiveTab(nextTab)
  }, [activeTab, saving])

  const saveFieldDrafts = useCallback(async () => {
    if (rowId === null || rowId === undefined) {
      message.error('Cannot update record without an ID')
      return
    }
    if (!dirtyFieldKeys.length) return

    const payload = Object.fromEntries(
      dirtyFieldKeys
        .map((key) => {
          const field = editableFieldMap.get(key)
          return field ? [key, normalizeEditableSaveValue(field, editDraft[key])] : null
        })
        .filter((entry): entry is [string, unknown] => entry !== null),
    )

    if (!Object.keys(payload).length) return

    setSaving(true)
    try {
      const { data } = await client.patch(`${config.endpoint}${rowId}/`, payload)
      setRecord(data)
      setLoadedRowId(rowId)
      clearFieldEditing()
      markChanged()
      message.success('Record updated')
    } catch (error) {
      const status = apiStatus(error)
      if (status === 404) {
        clearFieldEditing()
        message.warning('Record not found or has been deleted')
        onClose()
        return
      }

      const data = apiData(error)
      const nextFieldErrors = extractFieldErrors(data, dirtyFieldSet)
      if (Object.keys(nextFieldErrors).length) {
        setFieldErrors(nextFieldErrors)
        message.error('Failed to update record')
      } else {
        message.error(apiErrorMessage(data))
      }
    } finally {
      setSaving(false)
    }
  }, [clearFieldEditing, config.endpoint, dirtyFieldKeys, dirtyFieldSet, editDraft, editableFieldMap, markChanged, onClose, rowId])

  const fieldController = useMemo<FieldEditingController>(() => ({
    saving,
    dirtyCount: dirtyFieldKeys.length,
    hasDirtyFields,
    activeFieldKey,
    getFieldState: (key: string) => {
      const field = editableFieldMap.get(key)
      const hasDraft = Object.hasOwn(editDraft, key)
      const rawValue = hasDraft ? editDraft[key] : loadedCurrentRecord?.[key]
      const value = field ? normalizeEditableDraftValue(field, rawValue) : rawValue
      return {
        key,
        value,
        options: field?.options,
        editing: activeFieldKey === key,
        dirty: dirtyFieldSet.has(key),
        saving,
        error: fieldErrors[key],
      }
    },
    startFieldEdit: (key: string) => {
      const field = editableFieldMap.get(key)
      if (!field || !loadedCurrentRecord) {
        message.error('Field is not editable')
        return
      }
      setFieldErrors((previous) => removeFieldKey(previous, key))
      setEditDraft((previous) => {
        if (Object.hasOwn(previous, key)) return previous
        return {
          ...previous,
          [key]: normalizeEditableDraftValue(field, loadedCurrentRecord[key]),
        }
      })
      setActiveFieldKey(key)
    },
    setFieldDraftValue: (key: string, value: unknown) => {
      const field = editableFieldMap.get(key)
      if (!field) {
        message.error('Field is not editable')
        return
      }
      setFieldErrors((previous) => removeFieldKey(previous, key))
      setEditDraft((previous) => ({
        ...previous,
        [key]: normalizeEditableDraftValue(field, value),
      }))
    },
    finishFieldEdit: (key: string) => {
      const field = editableFieldMap.get(key)
      setActiveFieldKey((current) => current === key ? null : current)
      if (!field || !loadedCurrentRecord) return
      setEditDraft((previous) => {
        const value = Object.hasOwn(previous, key)
          ? previous[key]
          : normalizeEditableDraftValue(field, loadedCurrentRecord[key])
        return editableValuesEqual(field, loadedCurrentRecord[key], value)
          ? removeFieldKey(previous, key)
          : previous
      })
    },
    cancelFieldDraft: (key: string) => {
      setEditDraft((previous) => removeFieldKey(previous, key))
      setFieldErrors((previous) => removeFieldKey(previous, key))
      setActiveFieldKey((current) => current === key ? null : current)
    },
  }), [
    activeFieldKey,
    dirtyFieldKeys.length,
    dirtyFieldSet,
    editDraft,
    editableFieldMap,
    fieldErrors,
    hasDirtyFields,
    loadedCurrentRecord,
    saving,
  ])

  useEffect(() => {
    if (!open || rowId === null || rowId === undefined) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setRecord(null)
      setLoadedRowId(null)
      setLoading(false)
      setRefreshing(false)
      setSaving(false)
      setChangedSinceOpen(false)
      clearFieldEditing()
      return
    }
    setChangedSinceOpen(false)
    const nextActiveTab = initialTabKey && config.tabs.some((tab) => tab.key === initialTabKey)
      ? initialTabKey
      : 'basic'
    setActiveTab(nextActiveTab)
    setActivityDrawer(null)
    loadRecord(rowId, { reset: true })

    return () => {
      requestIdRef.current += 1
    }
  }, [clearFieldEditing, open, rowId, config.tabs, initialTabKey, loadRecord])

  const contentTabs = useMemo(() => [
    {
      key: 'basic',
      label: 'Basic',
      icon: <FileTextOutlined />,
      render: (currentRecord: Record<string, unknown>) => config.basicView
        ? config.basicView(currentRecord, {
          onOpenResource,
          onChanged: markChanged,
          fieldController,
        })
        : <RecordBasicView config={config} record={currentRecord} onOpenResource={onOpenResource} />,
    },
    ...config.tabs,
  ], [config, fieldController, markChanged, onOpenResource])

  const content = contentTabs.find((tab) => tab.key === activeTab)
  const objectId = loadedCurrentRecord ? String(loadedCurrentRecord.id || '') : ''
  const contentType = contentTypeMap[config.key] || config.key
  const recordTitle = String(loadedCurrentRecord?.title || loadedCurrentRecord?.name || loadedCurrentRecord?.username || loadedCurrentRecord?.value || loadedCurrentRecord?.case_id || loadedCurrentRecord?.alert_id || loadedCurrentRecord?.artifact_id || loadedCurrentRecord?.enrichment_id || loadedCurrentRecord?.playbook_id || loadedCurrentRecord?.knowledge_id || rowId || '')
  const modalHeight = 'calc(100dvh - 80px)'
  const showContentRail = contentTabs.length > 1
  const DetailHeaderActions = config.detailHeaderActions
  const toggleActivityDrawer = (drawer: ActivityDrawerKey) => {
    setActivityDrawer((current) => current === drawer ? null : drawer)
  }
  const shareUrl = useMemo(() => (
    rowId === null || rowId === undefined ? null : buildRecordShareUrl(config.key, rowId)
  ), [config.key, rowId])
  const copyShareUrl = useCallback(async () => {
    if (!shareUrl) {
      message.error('This record cannot be shared')
      return
    }
    if (!navigator.clipboard?.writeText) {
      message.error('Clipboard is not available')
      return
    }
    try {
      await navigator.clipboard.writeText(shareUrl)
      message.success('Share link copied')
    } catch {
      message.error('Failed to copy share link')
    }
  }, [shareUrl])

  return (
    <Modal
      open={open}
      onCancel={requestClose}
      footer={null}
      closable={false}
      width="calc(100vw - 96px)"
      style={{ top: 40, maxWidth: 'none', paddingBottom: 0 }}
      className="record-detail-modal"
      styles={{
        mask: { background: 'rgba(0, 0, 0, 0.78)' },
        container: {
          padding: 0,
          background: token.colorBgContainer,
          border: `1px solid ${token.colorBorderSecondary}`,
          boxShadow: '0 28px 88px rgba(0, 0, 0, 0.9), 0 0 0 1px rgba(255, 255, 255, 0.04)',
          overflow: 'hidden',
        },
        body: { padding: 0, height: modalHeight, background: token.colorBgContainer, overflow: 'hidden' },
      }}
      destroyOnHidden
    >
      <div style={{ display: 'flex', height: modalHeight, background: token.colorBgContainer, color: 'rgba(255,255,255,0.85)' }}>
        {showContentRail && (
          <div
            style={{
              width: railExpanded ? 180 : 56,
              borderRight: dividerBorder,
              background: token.colorBgContainer,
              display: 'flex',
              flexDirection: 'column',
              alignItems: railExpanded ? 'stretch' : 'center',
            }}
          >
            <Button
              type="text"
              icon={railExpanded ? <MenuFoldOutlined /> : <MenuUnfoldOutlined />}
              onClick={() => setRailExpanded((value) => !value)}
              style={{ margin: 8 }}
            />
            {contentTabs.map((tab) => (
              <Tooltip key={tab.key} title={railExpanded ? '' : tab.label} placement="right">
                <Button
                  type={activeTab === tab.key ? 'primary' : 'text'}
                  icon={tab.icon}
                  onClick={() => requestTabChange(tab.key)}
                  style={{ margin: 8, justifyContent: railExpanded ? 'flex-start' : 'center' }}
                >
                  {railExpanded ? tab.label : null}
                </Button>
              </Tooltip>
            ))}
          </div>
        )}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ height: 56, borderBottom: dividerBorder, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 16px' }}>
            <div style={{ minWidth: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ display: 'inline-flex', color: token.colorPrimary, fontSize: 28, flexShrink: 0, lineHeight: 1 }}>{config.icon}</span>
              <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div style={{ ...typography.detailTitle, color: token.colorTextHeading, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{recordTitle}</div>
                {loadedCurrentRecord && <RecordTimestampSummary record={loadedCurrentRecord} />}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0, marginLeft: 16 }}>
              {loadedCurrentRecord && DetailHeaderActions && (
                <>
                  <DetailHeaderActions
                    record={loadedCurrentRecord}
                    buttonStyle={headerActionButtonStyle}
                    disabled={rowId === null || rowId === undefined || saving}
                    refreshRecord={refreshAfterMutation}
                  />
                  <Divider vertical style={{ height: 24, margin: '8px 4px', borderColor: token.colorBorderSecondary }} />
                </>
              )}
              <Tooltip title="Copy share link">
                <Button
                  type="text"
                  size="large"
                  style={headerActionButtonStyle}
                  icon={<ShareAltOutlined />}
                  disabled={!loadedCurrentRecord || !shareUrl || saving}
                  onClick={copyShareUrl}
                />
              </Tooltip>
              <Tooltip title="Refresh record">
                <Button
                  type="text"
                  size="large"
                  style={headerActionButtonStyle}
                  icon={<ReloadOutlined spin={refreshing} />}
                  loading={refreshing}
                  disabled={!loadedCurrentRecord || rowId === null || rowId === undefined || saving}
                  onClick={requestRefresh}
                />
              </Tooltip>
              <Tooltip title="Comments">
                <Button
                  type={activityDrawer === 'comments' ? 'primary' : 'text'}
                  size="large"
                  style={headerActionButtonStyle}
                  icon={<MessageOutlined />}
                  disabled={!objectId}
                  onClick={() => toggleActivityDrawer('comments')}
                />
              </Tooltip>
              <Tooltip title="Log">
                <Button
                  type={activityDrawer === 'log' ? 'primary' : 'text'}
                  size="large"
                  style={headerActionButtonStyle}
                  icon={<HistoryOutlined />}
                  disabled={!objectId}
                  onClick={() => toggleActivityDrawer('log')}
                />
              </Tooltip>
              <Button type="text" size="large" style={headerActionButtonStyle} icon={<CloseOutlined />} disabled={saving} onClick={requestClose} />
            </div>
          </div>
          <div style={{ flex: 1, minHeight: 0, display: 'flex', position: 'relative' }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              {loading ? <Spin style={{ margin: 32 }} /> : loadedCurrentRecord ? content?.render(loadedCurrentRecord, { onOpenResource, onChanged: markChanged }) : <Empty style={{ margin: 32 }} description="No record loaded" />}
            </div>
            {activityDrawer && objectId && (
              <div style={{ width: 420, borderLeft: dividerBorder, display: 'flex', flexDirection: 'column', background: '#0f0f0f', minHeight: 0 }}>
                <div style={{ flex: 1, minHeight: 0, overflow: activityDrawer === 'comments' ? 'hidden' : 'auto', padding: 12, boxSizing: 'border-box' }}>
                  {activityDrawer === 'comments'
                    ? <DiscussionThread contentType={contentType} objectId={objectId} />
                    : <AuditTimeline contentType={contentType} objectId={objectId} onOpenResource={onOpenResource} />}
                </div>
              </div>
            )}
            {hasDirtyFields && activeTab === 'basic' && (
              <DetailDraftActionBar
                dirtyCount={dirtyFieldKeys.length}
                saving={saving}
                onCancel={clearFieldEditing}
                onSave={saveFieldDrafts}
              />
            )}
          </div>
        </div>
      </div>
    </Modal>
  )
}
