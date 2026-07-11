import {type CSSProperties, type KeyboardEvent, type ReactNode, useState} from 'react'
import {CheckCircleOutlined, DownOutlined, PauseCircleOutlined, PlusCircleOutlined, QuestionCircleOutlined, StopOutlined, SyncOutlined, UserOutlined,} from '@ant-design/icons'
import type {GetProps, InputProps, SelectProps} from 'antd'
import {Button, DatePicker, Input, InputNumber, Popover, Segmented, Select, Space, Switch, Tag} from 'antd'
import dayjs from 'dayjs'
import type {ChoiceOption} from '../types/records'
import MarkdownEditor from './MarkdownEditor'
import MarkdownPreview from './MarkdownPreview'
import {DESCRIPTION_VALUE_HEIGHT} from './descriptionValueStyles'
import {comfortableTagProps} from '../utils/tagStyles'
import {typography} from '../utils/typography'

interface InlineEditorProps<Value> {
  value: Value
  disabled?: boolean
  autoFocus?: boolean
  onChange: (value: Value) => void
  onComplete?: () => void
  onCancel?: () => void
}

interface SelectEditorProps extends InlineEditorProps<string | string[] | null> {
  options?: ChoiceOption[]
  allowClear?: boolean
  fallbackLabel?: ReactNode
  onStart?: () => void
}

interface InlineDateTimeEditorProps extends InlineEditorProps<string | null> {
  placeholder?: string
}

interface InlineTagChoiceEditorProps extends InlineEditorProps<string> {
  options?: ChoiceOption[]
  renderTag: (value: string, selected?: boolean) => ReactNode
  allowClear?: boolean
  clearLabel?: ReactNode
  onStart?: () => void
}

type TextAreaProps = GetProps<typeof Input.TextArea>

const editorWidthStyle = { width: '100%' }
const selectEditorStyle = { width: '100%', height: '100%', minWidth: 0 }
const inlineSelectStyles: SelectProps['styles'] = {
  root: { paddingInlineStart: 0 },
}
const inlineTagSelectStyles: SelectProps['styles'] = {
  ...inlineSelectStyles,
  item: {
    background: 'rgba(22,119,255,0.16)',
    borderColor: 'rgba(22,119,255,0.35)',
    color: '#69b1ff',
  },
  itemContent: {
    color: '#69b1ff',
  },
}
const inlineInputStyles: InputProps['styles'] = {
  input: { paddingInlineStart: 0 },
}
const inlineTextAreaStyles = {
  textarea: { paddingInlineStart: 0 },
} satisfies NonNullable<TextAreaProps['styles']>

function cancelOnEscape(event: KeyboardEvent, onCancel?: () => void) {
  if (event.key !== 'Escape') return
  event.stopPropagation()
  onCancel?.()
}

function datePickerValue(value: string | null) {
  if (!value) return null
  const parsed = dayjs(value)
  return parsed.isValid() ? parsed : null
}

function selectOptionColor(options: ChoiceOption[], value: unknown) {
  return options.find((option) => String(option.value) === String(value))?.color
}

function markerColor(color?: string) {
  const colors: Record<string, string> = {
    blue: '#1677ff',
    processing: '#1677ff',
    gold: '#faad14',
    green: '#52c41a',
    default: 'rgba(255,255,255,0.35)',
    purple: '#722ed1',
    magenta: '#eb2f96',
    red: '#ff4d4f',
    orange: '#fa8c16',
    cyan: '#13c2c2',
    geekblue: '#2f54eb',
    lime: '#a0d911',
    volcano: '#fa541c',
  }
  if (!color) return undefined
  return colors[color] || color
}

function semanticIcon(value: unknown, label: ReactNode) {
  const text = String(value || label || '').toLowerCase()
  if (text === 'new') return <PlusCircleOutlined />
  if (text.includes('progress')) return <SyncOutlined />
  if (text.includes('hold')) return <PauseCircleOutlined />
  if (text.includes('resolved')) return <CheckCircleOutlined />
  if (text.includes('closed')) return <StopOutlined />
  if (text.includes('unknown')) return <QuestionCircleOutlined />
  return <UserOutlined />
}

function SelectOptionLabel({ label, value, color }: { label: ReactNode; value?: unknown; color?: string }) {
  const resolvedColor = markerColor(color)
  const iconColor = resolvedColor || 'rgba(255,255,255,0.45)'
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
      <span style={{ color: iconColor, display: 'inline-flex', alignItems: 'center', fontSize: typography.tag.fontSize, flexShrink: 0 }}>
        {semanticIcon(value, label)}
      </span>
      <span style={{ color: resolvedColor, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
    </span>
  )
}

function compactTagRender(options: ChoiceOption[], defaultColor?: string): SelectProps['tagRender'] {
  return ({ label, value, closable, onClose }) => {
    const color = selectOptionColor(options, value) || defaultColor
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', lineHeight: 'normal' }}>
        <Tag
          {...comfortableTagProps}
          color={color}
          closable={closable}
          onClose={onClose}
          onMouseDown={(event) => {
            event.preventDefault()
            event.stopPropagation()
          }}
          style={{ marginInlineEnd: 0 }}
        >
          {label}
        </Tag>
      </span>
    )
  }
}

export function InlineTextEditor({ value, disabled, autoFocus = true, onChange, onComplete, onCancel }: InlineEditorProps<string>) {
  return (
    <Input
      autoFocus={autoFocus}
      variant="underlined"
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      onPressEnter={onComplete}
      onBlur={onComplete}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      styles={inlineInputStyles}
      style={editorWidthStyle}
    />
  )
}

export function InlineTextAreaEditor({ value, disabled, autoFocus = true, onChange, onComplete, onCancel }: InlineEditorProps<string>) {
  return (
    <Input.TextArea
      autoFocus={autoFocus}
      variant="underlined"
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      onBlur={onComplete}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      styles={inlineTextAreaStyles}
      style={{ ...editorWidthStyle, height: 86, resize: 'none' }}
    />
  )
}

export function InlineDateTimeEditor({ value, disabled, autoFocus = true, placeholder, onChange, onComplete, onCancel }: InlineDateTimeEditorProps) {
  return (
    <DatePicker
      autoFocus={autoFocus}
      variant="underlined"
      showTime
      allowClear
      placeholder={placeholder}
      value={datePickerValue(value)}
      disabled={disabled}
      onChange={(next) => onChange(next ? next.toISOString() : null)}
      onOpenChange={(open) => {
        if (!open) onComplete?.()
      }}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      style={editorWidthStyle}
    />
  )
}

export function InlineSelectEditor({ value, disabled, options = [], allowClear = true, fallbackLabel, onStart, onChange, onComplete, onCancel }: SelectEditorProps) {
  const optionRender: SelectProps['optionRender'] = (option) => (
    <SelectOptionLabel label={option.label} value={option.value} color={(option.data as ChoiceOption).color} />
  )
  const labelRender: SelectProps['labelRender'] = ({ label, value: selectedValue }) => (
    <SelectOptionLabel label={label || fallbackLabel || selectedValue} value={selectedValue} color={selectOptionColor(options, selectedValue)} />
  )

  return (
    <Select
      allowClear={allowClear}
      variant="borderless"
      value={typeof value === 'string' ? value : null}
      disabled={disabled}
      options={options}
      optionRender={optionRender}
      labelRender={labelRender}
      styles={inlineSelectStyles}
      onChange={(next) => {
        onChange(next ?? null)
        onComplete?.()
      }}
      onOpenChange={(open) => {
        if (open) onStart?.()
        else onComplete?.()
      }}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      style={selectEditorStyle}
    />
  )
}

export function InlineTagChoiceEditor({
  value,
  disabled,
  options = [],
  renderTag,
  allowClear = true,
  clearLabel = 'Clear',
  onStart,
  onChange,
  onComplete,
  onCancel,
}: InlineTagChoiceEditorProps) {
  const [open, setOpen] = useState(false)

  const completeAndClose = () => {
    setOpen(false)
    onComplete?.()
  }

  const selectValue = (next: string) => {
    onChange(next)
    completeAndClose()
  }

  return (
    <div style={{ minHeight: DESCRIPTION_VALUE_HEIGHT, height: DESCRIPTION_VALUE_HEIGHT, display: 'flex', alignItems: 'center', width: '100%', minWidth: 0 }}>
      <Popover
        trigger="click"
        open={open}
        onOpenChange={(nextOpen) => {
          if (disabled) return
          setOpen(nextOpen)
          if (nextOpen) onStart?.()
          else onComplete?.()
        }}
        content={(
          <div
            style={{ maxWidth: 420 }}
            onKeyDown={(event) => {
              if (event.key === 'Escape') {
                setOpen(false)
                onCancel?.()
              }
            }}
          >
            <Space size={[6, 8]} wrap>
              {options.map((option) => {
                const optionValue = String(option.value)
                const selected = optionValue === value
                return (
                  <button
                    key={optionValue}
                    type="button"
                    disabled={disabled}
                    onClick={() => selectValue(optionValue)}
                    style={{
                      padding: 0,
                      border: 0,
                      background: 'transparent',
                      cursor: disabled ? 'not-allowed' : 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                    }}
                  >
                    {renderTag(optionValue, selected)}
                  </button>
                )
              })}
              {allowClear && (
                <Button type="link" size="small" onClick={() => selectValue('')} disabled={disabled || value === ''}>
                  {clearLabel}
                </Button>
              )}
            </Space>
          </div>
        )}
      >
        <span style={{ display: 'block', width: '100%', minWidth: 0 }}>
          <button
            type="button"
            disabled={disabled}
            style={{
              padding: 0,
              border: 0,
              background: 'transparent',
              color: 'inherit',
              cursor: disabled ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              width: '100%',
              maxWidth: '100%',
            }}
          >
            <span style={{ minWidth: 0, overflow: 'hidden', display: 'inline-flex', alignItems: 'center' }}>
              {renderTag(value)}
            </span>
            <DownOutlined style={{ color: 'rgba(255,255,255,0.35)', fontSize: 10, marginLeft: 'auto', flexShrink: 0 }} />
          </button>
        </span>
      </Popover>
    </div>
  )
}

export function InlineMultiSelectEditor({ value, disabled, options = [], onStart, onChange, onComplete, onCancel }: SelectEditorProps) {
  const optionRender: SelectProps['optionRender'] = (option) => (
    <SelectOptionLabel label={option.label} value={option.value} color={(option.data as ChoiceOption).color} />
  )

  return (
    <Select
      mode="multiple"
      variant="borderless"
      value={Array.isArray(value) ? value : []}
      disabled={disabled}
      options={options}
      optionRender={optionRender}
      tagRender={compactTagRender(options)}
      styles={inlineSelectStyles}
      onChange={(next) => onChange(next)}
      onOpenChange={(open) => {
        if (open) onStart?.()
        else onComplete?.()
      }}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      style={selectEditorStyle}
    />
  )
}

export function InlineTagsEditor({ value, disabled, onStart, onChange, onComplete, onCancel }: InlineEditorProps<string[]> & { onStart?: () => void }) {
  return (
    <Select
      mode="tags"
      size="medium"
      variant="borderless"
      tokenSeparators={[',']}
      maxTagCount="responsive"
      value={value}
      disabled={disabled}
      styles={inlineTagSelectStyles}
      onChange={onChange}
      onOpenChange={(open) => {
        if (open) onStart?.()
        else onComplete?.()
      }}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      style={selectEditorStyle}
    />
  )
}

export function InlineUserEditor({ value, disabled, options = [], allowClear = true, fallbackLabel, onStart, onChange, onComplete, onCancel }: SelectEditorProps) {
  const optionRender: SelectProps['optionRender'] = (option) => (
    <SelectOptionLabel label={option.label} value={option.value} color={(option.data as ChoiceOption).color} />
  )
  const labelRender: SelectProps['labelRender'] = ({ label, value: selectedValue }) => (
    <SelectOptionLabel label={label || fallbackLabel || selectedValue} value={selectedValue} color={selectOptionColor(options, selectedValue)} />
  )

  return (
    <Select
      showSearch={{ optionFilterProp: 'label' }}
      allowClear={allowClear}
      variant="borderless"
      value={typeof value === 'string' ? value : null}
      disabled={disabled}
      options={options}
      optionRender={optionRender}
      labelRender={labelRender}
      styles={inlineSelectStyles}
      onChange={(next) => {
        onChange(next ?? null)
        onComplete?.()
      }}
      onOpenChange={(open) => {
        if (open) onStart?.()
        else onComplete?.()
      }}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      style={selectEditorStyle}
    />
  )
}

export function InlineNumberEditor({ value, disabled, onChange, onComplete, onCancel }: InlineEditorProps<number | null>) {
  return (
    <InputNumber
      autoFocus
      value={value}
      disabled={disabled}
      onChange={(next) => onChange(next)}
      onBlur={onComplete}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
      style={editorWidthStyle}
    />
  )
}

export function InlineBooleanEditor({ value, disabled, onChange, onComplete }: InlineEditorProps<boolean>) {
  return (
    <Switch
      autoFocus
      checked={value}
      disabled={disabled}
      onChange={(next) => {
        onChange(next)
        onComplete?.()
      }}
    />
  )
}

interface InlineMarkdownEditorProps extends InlineEditorProps<string> {
  height?: CSSProperties['height']
  defaultMode?: 'edit' | 'live' | 'preview'
}

export function InlineMarkdownEditor({ value, disabled, height = '100%', defaultMode = 'preview', onChange, onCancel }: InlineMarkdownEditorProps) {
  const [mode, setMode] = useState<'edit' | 'live' | 'preview'>(defaultMode)

  return (
    <div
      style={{ position: 'relative', height, width: '100%', minWidth: 0 }}
      onKeyDown={(event) => cancelOnEscape(event, onCancel)}
    >
      <Segmented
        value={mode}
        options={[
          { label: 'Edit', value: 'edit' },
          { label: 'Live', value: 'live' },
          { label: 'Preview', value: 'preview' },
        ]}
        onChange={(next) => setMode(next as 'edit' | 'live' | 'preview')}
        style={{ position: 'absolute', top: 8, right: 8, zIndex: 2 }}
      />
      {mode === 'edit' ? (
        <MarkdownEditor value={value} disabled={disabled} height={height} onChange={onChange} />
      ) : mode === 'live' ? (
        <MarkdownEditor value={value} disabled={disabled} height={height} preview="live" onChange={onChange} />
      ) : (
        <MarkdownPreview source={value} height={height} minHeight="100%" />
      )}
    </div>
  )
}
