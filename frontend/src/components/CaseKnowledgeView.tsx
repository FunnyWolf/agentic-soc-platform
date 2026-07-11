import {useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {Empty, Spin, theme} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'
import type {EditableFieldConfig, FieldEditingController, OpenResourceOptions} from '../types/records'
import DetailDraftActionBar from './DetailDraftActionBar'
import {editableValuesEqual, normalizeEditableDraftValue, normalizeEditableSaveValue} from './fieldEditing'
import KnowledgeBasicView from './KnowledgeBasicView'

type RecordRow = Record<string, unknown>

interface CaseKnowledgeViewProps {
  caseId: string
  editableFields: EditableFieldConfig[]
  onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
  onChanged?: () => void
}

function firstKnowledge(data: unknown): RecordRow | null {
  if (Array.isArray(data)) return data[0] as RecordRow | undefined || null
  const results = (data as { results?: unknown[] } | null)?.results
  return Array.isArray(results) ? (results[0] as RecordRow | undefined || null) : null
}

function apiErrorMessage(error: unknown) {
  const data = (error as { response?: { data?: unknown } }).response?.data
  if (typeof data === 'string') return data
  if (data && typeof data === 'object' && typeof (data as { detail?: unknown }).detail === 'string') {
    return (data as { detail: string }).detail
  }
  return 'Failed to load case knowledge'
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function errorText(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item)).join(' ')
  if (typeof value === 'string') return value
  if (isObjectRecord(value)) return JSON.stringify(value)
  return String(value)
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

export default function CaseKnowledgeView({ caseId, editableFields, onOpenResource, onChanged }: CaseKnowledgeViewProps) {
  const { token } = theme.useToken()
  const [knowledge, setKnowledge] = useState<RecordRow | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [editDraft, setEditDraft] = useState<Record<string, unknown>>({})
  const [activeFieldKey, setActiveFieldKey] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const requestIdRef = useRef(0)
  const editableFieldMap = useMemo(
    () => new Map(editableFields.map((field) => [field.key, field])),
    [editableFields],
  )
  const dirtyFieldKeys = useMemo(() => {
    if (!knowledge) return []
    return editableFields
      .filter((field) => (
        Object.hasOwn(editDraft, field.key)
        && !editableValuesEqual(field, knowledge[field.key], editDraft[field.key])
      ))
      .map((field) => field.key)
  }, [editDraft, editableFields, knowledge])
  const dirtyFieldSet = useMemo(() => new Set(dirtyFieldKeys), [dirtyFieldKeys])
  const hasDirtyFields = dirtyFieldKeys.length > 0

  const clearFieldEditing = useCallback(() => {
    setEditDraft({})
    setActiveFieldKey(null)
    setFieldErrors({})
  }, [])

  useEffect(() => {
    if (!caseId) return

    const requestId = requestIdRef.current + 1
    requestIdRef.current = requestId
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(true)
    client.get('/knowledge/', { params: { case: caseId, source: 'Case' } })
      .then(({ data }) => {
        if (requestId !== requestIdRef.current) return
        setKnowledge(firstKnowledge(data))
        clearFieldEditing()
      })
      .catch((error) => {
        if (requestId !== requestIdRef.current) return
        setKnowledge(null)
        clearFieldEditing()
        message.error(apiErrorMessage(error))
      })
      .finally(() => {
        if (requestId === requestIdRef.current) setLoading(false)
      })

    return () => {
      requestIdRef.current += 1
    }
  }, [caseId, clearFieldEditing])

  const saveFieldDrafts = useCallback(async () => {
    const knowledgeId = knowledge?.id
    if (typeof knowledgeId !== 'string' && typeof knowledgeId !== 'number') {
      message.error('Cannot update knowledge without an ID')
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
      const { data } = await client.patch(`/knowledge/${knowledgeId}/`, payload)
      setKnowledge(data)
      clearFieldEditing()
      onChanged?.()
      message.success('Knowledge updated')
    } catch (error) {
      const response = error as { response?: { status?: number; data?: unknown } }
      if (response.response?.status === 404) {
        setKnowledge(null)
        clearFieldEditing()
        message.warning('Knowledge not found or has been deleted')
        return
      }

      const nextFieldErrors = extractFieldErrors(response.response?.data, dirtyFieldSet)
      if (Object.keys(nextFieldErrors).length) {
        setFieldErrors(nextFieldErrors)
        message.error('Failed to update knowledge')
      } else {
        message.error(apiErrorMessage(error))
      }
    } finally {
      setSaving(false)
    }
  }, [clearFieldEditing, dirtyFieldKeys, dirtyFieldSet, editDraft, editableFieldMap, knowledge, onChanged])

  const fieldController = useMemo<FieldEditingController>(() => ({
    saving,
    dirtyCount: dirtyFieldKeys.length,
    hasDirtyFields,
    activeFieldKey,
    getFieldState: (key: string) => {
      const field = editableFieldMap.get(key)
      const hasDraft = Object.hasOwn(editDraft, key)
      const rawValue = hasDraft ? editDraft[key] : knowledge?.[key]
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
      if (!field || !knowledge) {
        message.error('Field is not editable')
        return
      }
      setFieldErrors((previous) => removeFieldKey(previous, key))
      setEditDraft((previous) => {
        if (Object.hasOwn(previous, key)) return previous
        return {
          ...previous,
          [key]: normalizeEditableDraftValue(field, knowledge[key]),
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
      if (!field || !knowledge) return
      setEditDraft((previous) => {
        const value = Object.hasOwn(previous, key)
          ? previous[key]
          : normalizeEditableDraftValue(field, knowledge[key])
        return editableValuesEqual(field, knowledge[key], value)
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
    knowledge,
    saving,
  ])

  if (!caseId) {
    return (
      <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Empty description="No case selected" />
      </div>
    )
  }

  if (loading) return <Spin style={{ margin: 32 }} />

  if (!knowledge) {
    return (
      <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Empty description="No extracted knowledge for this case" />
      </div>
    )
  }

  return (
    <div style={{ height: '100%', minHeight: 0, position: 'relative', background: token.colorBgContainer }}>
      <KnowledgeBasicView
        record={knowledge}
        fieldController={fieldController}
        onOpenResource={onOpenResource}
      />
      {hasDirtyFields && (
        <DetailDraftActionBar
          dirtyCount={dirtyFieldKeys.length}
          saving={saving}
          onCancel={clearFieldEditing}
          onSave={saveFieldDrafts}
        />
      )}
    </div>
  )
}
