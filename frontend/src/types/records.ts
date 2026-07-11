import type {ComponentType, CSSProperties, ReactNode} from 'react'
import type {ColumnsType} from 'antd/es/table'

type FixedColumn = boolean | 'left' | 'right'

export interface ChoiceOption {
  label: string
  value: string
  color?: string
}

export interface ResourceMetadata {
  label: string
  endpoint: string
  fields: Record<string, { label: string; type: string; has_choices: boolean }>
  choices: Record<string, ChoiceOption[]>
  search: string[]
  filters: string[]
  ordering: string[]
}

export interface MetadataResponse {
  resources: Record<string, ResourceMetadata>
}

export interface ResourceFilterConfig {
  key: string
  label: string
  options?: ChoiceOption[]
  valueType?: FilterValueType
  width?: number
}

export type FilterValueType = 'text' | 'select' | 'multi-select' | 'tag' | 'user' | 'date' | 'number'

export interface AdvancedFilterFieldConfig {
  key: string
  label: string
  valueType: FilterValueType
  options?: ChoiceOption[]
}

export interface AdvancedFilterCondition {
  id: string
  connector: 'and' | 'or'
  field: string
  operator: string
  value?: string | string[]
}

export interface TableFilterState {
  quick: Record<string, string | string[]>
  advanced: AdvancedFilterCondition[]
}

export interface SavedTableFilter {
  id: number
  table_key: string
  name: string
  state: TableFilterState
  visibility: 'private' | 'shared'
  owner_id: number
  owner_username: string
  can_edit: boolean
  created_at: string
  updated_at: string
}

export interface EditableFieldConfig {
  key: string
  type?: EditableFieldType
  emptyValue?: unknown
  options?: ChoiceOption[]
}

export type EditableFieldType =
  | 'text'
  | 'textarea'
  | 'markdown'
  | 'datetime'
  | 'select'
  | 'multiSelect'
  | 'tags'
  | 'user'
  | 'number'
  | 'boolean'

export interface EditableFieldState {
  key: string
  value: unknown
  options?: ChoiceOption[]
  editing: boolean
  dirty: boolean
  saving: boolean
  error?: string
}

export interface FieldEditingController {
  saving: boolean
  dirtyCount: number
  hasDirtyFields: boolean
  activeFieldKey: string | null
  getFieldState: (key: string) => EditableFieldState
  startFieldEdit: (key: string) => void
  setFieldDraftValue: (key: string, value: unknown) => void
  finishFieldEdit: (key: string) => void
  cancelFieldDraft: (key: string) => void
}

export interface ResourceColumn<RecordType = Record<string, unknown>> {
  key: string
  title: string
  dataIndex?: string
  required?: boolean
  defaultVisible?: boolean
  width?: number
  sorter?: boolean
  fixed?: FixedColumn
  openRecord?: boolean
  openRecordTab?: string
  openResource?: {
    resourceKey: string | ((record: RecordType) => string | null | undefined)
    rowId: (record: RecordType) => string | number | null | undefined
  }
  uppercase?: boolean
  render?: (value: unknown, record: RecordType) => ReactNode
}

export interface OpenResourceOptions {
  onChanged?: () => void
}

export interface BasicField<RecordType = Record<string, unknown>> {
  label: string
  value: (record: RecordType) => ReactNode
  mono?: boolean
  tag?: boolean
  color?: (record: RecordType) => string | undefined
  openResource?: {
    resourceKey: string | ((record: RecordType) => string | null | undefined)
    rowId: (record: RecordType) => string | number | null | undefined
  }
}

export interface BasicSection<RecordType = Record<string, unknown>> {
  key: string
  title: string
  fields: BasicField<RecordType>[]
}

export interface RecordTab<RecordType = Record<string, unknown>> {
  key: string
  label: string
  icon: ReactNode
  render: (record: RecordType, options?: {
    onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
    onChanged?: () => void
  }) => ReactNode
}

export interface DetailHeaderActionProps<RecordType = Record<string, unknown>> {
  record: RecordType
  buttonStyle?: CSSProperties
  disabled?: boolean
  refreshRecord: () => void
}

export interface ResourceConfig<RecordType = Record<string, unknown>> {
  key: string
  label: string
  icon?: ReactNode
  endpoint: string
  rowKey: string
  searchPlaceholder: string
  columns: ResourceColumn<RecordType>[]
  filters: ResourceFilterConfig[]
  advancedFilters?: AdvancedFilterFieldConfig[]
  editableFields?: EditableFieldConfig[]
  basicView?: (record: RecordType, options?: {
    onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
    onChanged?: () => void
    fieldController?: FieldEditingController
  }) => ReactNode
  detailHeaderActions?: ComponentType<DetailHeaderActionProps<RecordType>>
  showShare?: boolean
  showActivity?: boolean
  basicSections: BasicSection<RecordType>[]
  tabs: RecordTab<RecordType>[]
}

export type AntColumns<RecordType = Record<string, unknown>> = ColumnsType<RecordType>
