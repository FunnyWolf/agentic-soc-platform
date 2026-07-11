import {useEffect, useMemo, useState} from 'react'
import {App as AntApp, Button, DatePicker, Divider, Dropdown, Empty, Input, InputNumber, Modal, Select, Space, Tag, Typography} from 'antd'
import {ClearOutlined, CloseOutlined, PlusOutlined, SaveOutlined, SearchOutlined} from '@ant-design/icons'
import dayjs from 'dayjs'
import type {AdvancedFilterCondition, AdvancedFilterFieldConfig, ChoiceOption, ResourceMetadata, SavedTableFilter, TableFilterState} from '../types/records'
import client from '../api/client'
import {createSavedTableFilter, deleteSavedTableFilter, fetchSavedTableFilters, updateSavedTableFilter} from '../api/preferences'
import {comfortableCheckableTagGroupProps, comfortableTagProps} from '../utils/tagStyles'

const { RangePicker } = DatePicker
export const TABLE_FILTER_MODAL_WIDTH = 1300
const CURRENT_FILTER_PANEL_WIDTH = 900
const SAVED_FILTER_PANEL_WIDTH = 340

interface TableFilterModalProps {
  open: boolean
  savedFiltersKey: string
  advancedFilters?: AdvancedFilterFieldConfig[]
  metadata?: ResourceMetadata
  value: TableFilterState
  position?: { top: number; left: number }
  onSavedFilterNameChange?: (name: string) => void
  onChange: (value: TableFilterState) => void
  onClose: () => void
}

const operatorOptions = {
  text: [
    { label: 'Equals', value: 'eq' },
    { label: 'Does not equal', value: 'neq' },
    { label: 'Contains', value: 'contains' },
    { label: 'Contains all', value: 'contains_all' },
    { label: 'Does not contain', value: 'not_contains' },
    { label: 'Is empty', value: 'is_empty' },
    { label: 'Is not empty', value: 'is_not_empty' },
  ],
  select: [
    { label: 'Is', value: 'is' },
    { label: 'Is not', value: 'is_not' },
    { label: 'Is one of', value: 'is_one_of' },
    { label: 'Is not any of', value: 'is_not_any_of' },
    { label: 'Is empty', value: 'is_empty' },
    { label: 'Is not empty', value: 'is_not_empty' },
  ],
  tag: [
    { label: 'Contains any', value: 'contains_any' },
    { label: 'Does not contain any', value: 'not_contains_any' },
    { label: 'Contains all', value: 'contains_all' },
    { label: 'Is empty', value: 'is_empty' },
    { label: 'Is not empty', value: 'is_not_empty' },
  ],
  date: [
    { label: 'Equals', value: 'eq' },
    { label: 'Does not equal', value: 'neq' },
    { label: 'Before', value: 'lt' },
    { label: 'After', value: 'gt' },
    { label: 'On or before', value: 'lte' },
    { label: 'On or after', value: 'gte' },
    { label: 'Between', value: 'between' },
    { label: 'Not between', value: 'not_between' },
    { label: 'Is empty', value: 'is_empty' },
    { label: 'Is not empty', value: 'is_not_empty' },
  ],
  number: [
    { label: 'Equals', value: 'eq' },
    { label: 'Does not equal', value: 'neq' },
    { label: 'Greater than', value: 'gt' },
    { label: 'Greater than or equal to', value: 'gte' },
    { label: 'Less than', value: 'lt' },
    { label: 'Less than or equal to', value: 'lte' },
    { label: 'Between', value: 'between' },
    { label: 'Not between', value: 'not_between' },
    { label: 'Is empty', value: 'is_empty' },
    { label: 'Is not empty', value: 'is_not_empty' },
  ],
}

function fieldIcon(field: AdvancedFilterFieldConfig) {
  if (field.valueType === 'date') return '∑'
  if (field.valueType === 'number') return '#'
  if (field.valueType === 'tag' || field.valueType === 'multi-select') return '⌘'
  if (field.valueType === 'user') return '●'
  if (field.key.endsWith('_id') || field.key === 'id') return '#'
  return field.valueType === 'select' ? '▾' : 'A'
}

function normalizeType(field: AdvancedFilterFieldConfig) {
  if (field.valueType === 'multi-select' || field.valueType === 'user') return 'select'
  if (field.valueType === 'tag') return 'tag'
  if (field.valueType === 'date') return 'date'
  if (field.valueType === 'number') return 'number'
  return field.valueType === 'select' ? 'select' : 'text'
}

function conditionOperators(field: AdvancedFilterFieldConfig) {
  return operatorOptions[normalizeType(field)]
}

function defaultOperator(field: AdvancedFilterFieldConfig) {
  return conditionOperators(field)[0]?.value || 'eq'
}

function conditionSummary(state: TableFilterState) {
  const advancedCount = state.advanced.filter((item) => item.field && item.operator).length
  return `${advancedCount} condition(s)`
}

function savedStateFrom(advanced: AdvancedFilterCondition[]): TableFilterState {
  return { quick: {}, advanced }
}

function sameAdvancedFilters(left: AdvancedFilterCondition[], right: AdvancedFilterCondition[]) {
  return JSON.stringify(left) === JSON.stringify(right)
}

export default function TableFilterModal({
  open,
  savedFiltersKey,
  advancedFilters,
  metadata,
  value,
  position,
  onSavedFilterNameChange,
  onChange,
  onClose,
}: TableFilterModalProps) {
  const { message } = AntApp.useApp()
  const [savedFilters, setSavedFilters] = useState<SavedTableFilter[]>([])
  const [savedFiltersLoading, setSavedFiltersLoading] = useState(false)
  const [saveName, setSaveName] = useState('')
  const [saveVisibility, setSaveVisibility] = useState<SavedTableFilter['visibility']>('private')
  const [loadedSavedFilterId, setLoadedSavedFilterId] = useState<number | null>(null)
  const [userOptions, setUserOptions] = useState<ChoiceOption[]>([])
  const [draftAdvanced, setDraftAdvanced] = useState<AdvancedFilterCondition[]>(value.advanced)

  const handleAfterOpenChange = (visible: boolean) => {
    if (!visible) return
    setDraftAdvanced(value.advanced)
    setSaveName('')
    setSaveVisibility('private')
    setLoadedSavedFilterId(null)
    setSavedFiltersLoading(true)
    fetchSavedTableFilters(savedFiltersKey)
      .then(setSavedFilters)
      .catch(() => {
        setSavedFilters([])
        message.error('Failed to load saved filters')
      })
      .finally(() => setSavedFiltersLoading(false))
  }

  const fields = useMemo<AdvancedFilterFieldConfig[]>(() => {
    const base: AdvancedFilterFieldConfig[] = advancedFilters || []
    return base.map((field) => ({
      ...field,
      options: field.options || metadata?.choices?.[field.key],
    }))
  }, [advancedFilters, metadata])

  useEffect(() => {
    if (!open || !fields.some((field) => field.valueType === 'user')) return
    client.get('/auth/user-options/')
      .then(({ data }) => setUserOptions(data))
      .catch(() => setUserOptions([]))
  }, [fields, open])

  const updateCondition = (id: string, patch: Partial<AdvancedFilterCondition>) => {
    setDraftAdvanced((previous) => previous.map((condition) => (
        condition.id === id ? { ...condition, ...patch } : condition
      )))
  }
  const removeCondition = (id: string) => {
    setDraftAdvanced((previous) => previous.filter((condition) => condition.id !== id))
  }
  const addCondition = (fieldKey: string) => {
    const selectedField = fields.find((field) => field.key === fieldKey)
    if (!selectedField) return
    setDraftAdvanced((previous) => [
        ...previous,
        {
          id: `${Date.now()}-${fieldKey}`,
          connector: 'and',
          field: selectedField.key,
          operator: defaultOperator(selectedField),
          value: '',
        },
      ])
  }
  const clearFilters = () => {
    setDraftAdvanced([])
    setLoadedSavedFilterId(null)
    setSaveName('')
    setSaveVisibility('private')
  }
  const applyFilters = () => {
    const loadedFilter = loadedSavedFilterId
      ? savedFilters.find((item) => item.id === loadedSavedFilterId)
      : undefined
    const loadedFilterStillMatches = Boolean(
      loadedFilter && sameAdvancedFilters(loadedFilter.state.advanced, draftAdvanced),
    )
    onChange({ ...value, advanced: draftAdvanced })
    onSavedFilterNameChange?.(loadedFilterStillMatches ? loadedFilter?.name || '' : '')
  }
  const saveAsFilter = async () => {
    const trimmedName = saveName.trim()
    if (!trimmedName) {
      message.warning('Please enter a filter name')
      return
    }
    try {
      const created = await createSavedTableFilter({
        table_key: savedFiltersKey,
        name: trimmedName,
        state: savedStateFrom(draftAdvanced),
        visibility: saveVisibility,
      })
      setSavedFilters((previous) => [created, ...previous])
      message.success('Filter saved')
      setLoadedSavedFilterId(null)
      setSaveName('')
      setSaveVisibility('private')
    } catch {
      message.error('Failed to save filter')
    }
  }
  const updateLoadedFilter = async () => {
    if (!loadedSavedFilterId) return
    const loadedFilter = savedFilters.find((item) => item.id === loadedSavedFilterId)
    if (!loadedFilter?.can_edit) {
      message.warning('You can only update filters you own')
      return
    }
    const trimmedName = saveName.trim()
    if (!trimmedName) {
      message.warning('Please enter a filter name')
      return
    }
    try {
      const updated = await updateSavedTableFilter(loadedSavedFilterId, {
        name: trimmedName,
        state: savedStateFrom(draftAdvanced),
        visibility: saveVisibility,
      })
      setSavedFilters((previous) => previous.map((item) => item.id === updated.id ? updated : item))
      message.success('Filter updated')
    } catch {
      message.error('Failed to update filter')
    }
  }
  const deleteSavedFilter = async (item: SavedTableFilter) => {
    if (!item.can_edit) {
      message.warning('You can only delete filters you own')
      return
    }
    try {
      await deleteSavedTableFilter(item.id)
      setSavedFilters((previous) => previous.filter((saved) => saved.id !== item.id))
      if (loadedSavedFilterId === item.id) {
        setLoadedSavedFilterId(null)
        setSaveName('')
        setSaveVisibility('private')
      }
    } catch {
      message.error('Failed to delete filter')
    }
  }
  const loadSavedFilter = (item: SavedTableFilter) => {
    setDraftAdvanced(item.state.advanced)
    setSaveName(item.name)
    setSaveVisibility(item.visibility)
    setLoadedSavedFilterId(item.id)
  }

  const renderChoiceTags = (condition: AdvancedFilterCondition, options: ChoiceOption[], multiple = true) => {
    const selectedValues = Array.isArray(condition.value) ? condition.value : condition.value ? [condition.value] : []
    const groupOptions = options.map((option) => ({ value: option.value, label: option.label }))

    if (!multiple) {
      return (
        <Tag.CheckableTagGroup
          {...comfortableCheckableTagGroupProps}
          options={groupOptions}
          value={selectedValues[0] ?? null}
          onChange={(next) => updateCondition(condition.id, { value: next ?? '' })}
          style={{ width: '100%', overflowX: 'auto', paddingBottom: 2 }}
        />
      )
    }

    return (
      <Tag.CheckableTagGroup
        {...comfortableCheckableTagGroupProps}
        multiple
        options={groupOptions}
        value={selectedValues}
        onChange={(next) => updateCondition(condition.id, { value: next })}
        style={{ width: '100%', overflowX: 'auto', paddingBottom: 2 }}
      />
    )
  }

  const renderConditionValue = (condition: AdvancedFilterCondition, field: AdvancedFilterFieldConfig) => {
    if (condition.operator === 'is_empty' || condition.operator === 'is_not_empty') return null
    const multiple = ['is_one_of', 'is_not_any_of', 'contains_any', 'not_contains_any', 'contains_all'].includes(condition.operator)
    const options = field.valueType === 'user' ? [...(field.options || []), ...userOptions] : field.options || []

    if (field.valueType === 'select' || field.valueType === 'multi-select') {
      return renderChoiceTags(condition, options, multiple)
    }
    if (field.valueType === 'tag') {
      return (
        <Select
          mode="tags"
          placeholder="Please enter tags"
          style={{ width: '100%' }}
          options={options}
          tagRender={({ label, value, closable, onClose }) => (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                marginInlineEnd: 8,
                color: `var(--ant-color-${Math.abs(String(value).length % 10) + 1}, #1677ff)`,
              }}
            >
              {label}
              {closable && (
                <CloseOutlined
                  style={{ fontSize: 10, color: 'rgba(255,255,255,0.45)' }}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={onClose}
                />
              )}
            </span>
          )}
          value={Array.isArray(condition.value) ? condition.value : condition.value ? [condition.value] : []}
          onChange={(next) => updateCondition(condition.id, { value: next })}
        />
      )
    }
    if (field.valueType === 'user') {
      return (
        <Select
          mode={multiple ? 'multiple' : undefined}
          placeholder="Select users"
          showSearch
          style={{ width: '100%' }}
          options={userOptions}
          value={condition.value || undefined}
          onChange={(next) => updateCondition(condition.id, { value: next || '' })}
        />
      )
    }
    if (field.valueType === 'date') {
      if (condition.operator === 'between' || condition.operator === 'not_between') {
        const dateValues = Array.isArray(condition.value) ? condition.value : []
        return (
          <RangePicker
            showTime
            style={{ width: '100%' }}
            value={dateValues.length === 2 ? [dayjs(dateValues[0]), dayjs(dateValues[1])] : undefined}
            onChange={(_, dateStrings) => updateCondition(condition.id, { value: dateStrings.filter(Boolean) })}
          />
        )
      }
      return (
        <DatePicker
          showTime
          style={{ width: '100%' }}
          value={typeof condition.value === 'string' && condition.value ? dayjs(condition.value) : undefined}
          onChange={(_, dateString) => updateCondition(condition.id, { value: String(dateString || '') })}
        />
      )
    }
    if (field.valueType === 'number') {
      if (condition.operator === 'between' || condition.operator === 'not_between') {
        const values = Array.isArray(condition.value) ? condition.value : []
        return (
          <Space.Compact style={{ width: '100%' }}>
            <InputNumber style={{ width: '50%' }} value={values[0] !== undefined && values[0] !== '' ? Number(values[0]) : undefined} onChange={(next) => updateCondition(condition.id, { value: [next === null ? '' : String(next), values[1] || ''] })} />
            <InputNumber style={{ width: '50%' }} value={values[1] !== undefined && values[1] !== '' ? Number(values[1]) : undefined} onChange={(next) => updateCondition(condition.id, { value: [values[0] || '', next === null ? '' : String(next)] })} />
          </Space.Compact>
        )
      }
      return <InputNumber style={{ width: '100%' }} value={condition.value !== undefined && condition.value !== '' ? Number(condition.value) : undefined} onChange={(next) => updateCondition(condition.id, { value: next === null ? '' : String(next) })} />
    }
    return (
      <Input
        placeholder="Please enter"
        value={Array.isArray(condition.value) ? condition.value.join(', ') : condition.value}
        onChange={(event) => updateCondition(condition.id, { value: event.target.value })}
      />
    )
  }

  const currentFilterPanel = (
    <Space vertical size={18} style={{ width: '100%', height: '100%' }}>
      <Space vertical style={{ width: '100%' }} size={16}>
        {draftAdvanced.map((condition, index) => {
          const selectedField = fields.find((field) => field.key === condition.field) || fields[0]
          if (!selectedField) return null
          const operators = conditionOperators(selectedField)
          return (
            <div key={condition.id} style={{ borderTop: index === 0 ? undefined : '1px solid #303030', paddingTop: index === 0 ? 0 : 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '64px 28px 180px 160px 32px', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <div>
                  {index === 0 ? (
                    <div style={{ width: 64, display: 'flex', alignItems: 'center', paddingInlineStart: 15 }}>
                      <Typography.Text type="secondary">Where</Typography.Text>
                    </div>
                  ) : (
                    <Dropdown
                      trigger={['click']}
                      menu={{
                        items: [{ key: 'and', label: 'And' }, { key: 'or', label: 'Or' }],
                        onClick: ({ key }) => updateCondition(condition.id, { connector: key === 'or' ? 'or' : 'and' }),
                      }}
                    >
                      <Button type="text">
                        {condition.connector === 'or' ? 'Or' : 'And'}
                      </Button>
                    </Dropdown>
                  )}
                </div>
                <Typography.Text type="secondary" style={{ textAlign: 'center' }}>{fieldIcon(selectedField)}</Typography.Text>
                <Typography.Text strong>{selectedField.label}</Typography.Text>
                <Select
                  variant="borderless"
                  style={{ width: '100%' }}
                  value={condition.operator}
                  options={operators}
                  onChange={(next) => updateCondition(condition.id, { operator: next, value: '' })}
                />
                <Button type="text" icon={<CloseOutlined />} onClick={() => removeCondition(condition.id)} />
              </div>
              <div style={{ paddingLeft: 64 + 8 + 28 + 8 }}>
                {renderConditionValue(condition, selectedField)}
              </div>
            </div>
          )
        })}
      </Space>
      <div style={{ marginTop: 'auto', borderTop: '1px solid #303030', paddingTop: 12 }}>
        <Space wrap={false} style={{ width: '100%', overflowX: 'auto', paddingBottom: 2 }}>
          <Dropdown
            trigger={['click']}
            menu={{
              items: fields.map((field) => ({ key: field.key, label: field.label })),
              onClick: ({ key }) => addCondition(String(key)),
            }}
          >
            <Button icon={<PlusOutlined />}>Add filter</Button>
          </Dropdown>
          <Input placeholder="Filter name" value={saveName} onChange={(event) => setSaveName(event.target.value)} style={{ width: 240, flexShrink: 0 }} />
          <Select
           value={saveVisibility}
           style={{ width: 112, flexShrink: 0 }}
           options={[{ label: 'Private', value: 'private' }, { label: 'Shared', value: 'shared' }]}
           onChange={(next: SavedTableFilter['visibility']) => setSaveVisibility(next)}
          />
          {loadedSavedFilterId && <Button icon={<SaveOutlined />} disabled={!savedFilters.find((item) => item.id === loadedSavedFilterId)?.can_edit} onClick={updateLoadedFilter} style={{ flexShrink: 0 }}>Update</Button>}
          <Button icon={<SaveOutlined />} onClick={saveAsFilter} style={{ flexShrink: 0 }}>Save as</Button>
          <Button icon={<ClearOutlined />} onClick={clearFilters} style={{ flexShrink: 0 }}>Clear</Button>
          <Button type="primary" icon={<SearchOutlined />} onClick={applyFilters} style={{ flexShrink: 0 }}>Search</Button>
        </Space>
      </div>
    </Space>
  )

  const savedPanel = savedFiltersLoading ? (
    <Empty description="Loading saved filters..." />
  ) : savedFilters.length ? (
    <Space vertical size={8} style={{ width: '100%' }}>
      {savedFilters.map((item) => (
        <div
          key={item.id}
          style={{
            border: '1px solid #303030',
            borderRadius: 8,
            padding: '8px 10px',
            background: loadedSavedFilterId === item.id ? 'rgba(22, 119, 255, 0.12)' : undefined,
          }}
        >
          <Typography.Text strong ellipsis style={{ display: 'block', maxWidth: '100%' }}>
            {item.name}
          </Typography.Text>
          <Typography.Text type="secondary" ellipsis style={{ display: 'block', maxWidth: '100%', fontSize: 12 }}>
           {item.visibility === 'shared' ? `Shared by ${item.owner_username}` : 'Private'}
          </Typography.Text>
          <div style={{ display: 'grid', gridTemplateColumns: 'auto max-content', alignItems: 'center', gap: 8, marginTop: 6 }}>
           <Space size={4} wrap>
             <Tag {...comfortableTagProps} color="blue" style={{ marginInlineEnd: 0, width: 'fit-content', maxWidth: '100%' }}>
               {conditionSummary(item.state)}
             </Tag>
             <Tag {...comfortableTagProps} color={item.visibility === 'shared' ? 'green' : 'default'} style={{ marginInlineEnd: 0 }}>
               {item.visibility}
             </Tag>
           </Space>
           <Space size={4} wrap={false}>
             <Button size="small" type="link" onClick={() => loadSavedFilter(item)}>Load</Button>
             <Button size="small" type="link" danger disabled={!item.can_edit} onClick={() => deleteSavedFilter(item)}>Delete</Button>
           </Space>
          </div>
        </div>
      ))}
    </Space>
  ) : <Empty description="No saved filters" />

  return (
    <Modal
      open={open}
      onCancel={onClose}
      footer={null}
      width={Math.min(TABLE_FILTER_MODAL_WIDTH, window.innerWidth - 32)}
      mask={false}
      style={{ top: position?.top ?? 80, left: position?.left, margin: 0, paddingBottom: 0 }}
      afterOpenChange={handleAfterOpenChange}
      destroyOnHidden
    >
      <div style={{ display: 'grid', gridTemplateColumns: `${CURRENT_FILTER_PANEL_WIDTH}px ${SAVED_FILTER_PANEL_WIDTH}px`, gap: 20, minHeight: 420 }}>
        <section style={{ minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          <Typography.Title level={5} style={{ marginTop: 0 }}>Current filters</Typography.Title>
          {currentFilterPanel}
        </section>
        <section style={{ borderLeft: '1px solid #303030', paddingLeft: 16, minWidth: 0 }}>
          <Typography.Title level={5} style={{ marginTop: 0 }}>Saved filters</Typography.Title>
          <Divider style={{ margin: '8px 0 16px' }} />
          {savedPanel}
        </section>
      </div>
    </Modal>
  )
}
