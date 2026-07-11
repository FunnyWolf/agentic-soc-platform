import type {DescriptionsProps} from 'antd'
import {Button, Descriptions, Tag, theme} from 'antd'
import type {FieldEditingController, OpenResourceOptions} from '../types/records'
import {DescriptionValue, EditableDescriptionValue} from './DescriptionValue'
import {descriptionStyles} from './descriptionValueStyles'
import {InlineDateTimeEditor, InlineMarkdownEditor, InlineTagsEditor, InlineTextEditor} from './InlineFieldEditors'
import MarkdownPreview from './MarkdownPreview'
import {emptyValue, emptyValueNode, formatDateTime, knowledgeSourceTag} from '../utils/recordDisplay'
import {comfortableTagProps} from '../utils/tagStyles'
import {editableLabel} from './editableLabel'
import {typography} from '../utils/typography'

type RecordRow = Record<string, unknown>

interface KnowledgeBasicViewProps {
  record: RecordRow
  fieldController?: FieldEditingController
  onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
}

const value = (record: RecordRow, key: string) => record[key]
const stringValue = (record: RecordRow, key: string) => emptyValue(value(record, key))
const upperStringValue = (record: RecordRow, key: string) => {
  const displayValue = stringValue(record, key)
  return displayValue === '—' ? displayValue : displayValue.toUpperCase()
}
const mono = (children: string) => <DescriptionValue mono>{children}</DescriptionValue>
const arrayValue = (items: unknown) => Array.isArray(items) ? items.map((item) => String(item)) : []

function renderTags(items: unknown) {
  const values = arrayValue(items)
  if (!values.length) return emptyValueNode()
  return (
    <span style={{ display: 'inline-flex', flexWrap: 'nowrap', gap: 4, overflow: 'hidden' }}>
      {values.map((item) => <Tag {...comfortableTagProps} key={item} color="blue" style={{ marginInlineEnd: 0, flexShrink: 0 }}>{item}</Tag>)}
    </span>
  )
}

export default function KnowledgeBasicView({ record, fieldController, onOpenResource }: KnowledgeBasicViewProps) {
  const { token } = theme.useToken()
  const controller = fieldController
  const titleState = controller?.getFieldState('title')
  const expiresAtState = controller?.getFieldState('expires_at')
  const tagsState = controller?.getFieldState('tags')
  const bodyState = controller?.getFieldState('body')
  const caseId = value(record, 'case')
  const caseRowId = typeof caseId === 'string' || typeof caseId === 'number' ? caseId : null
  const caseReadableId = upperStringValue(record, 'case_readable_id')
  const source = String(value(record, 'source') || '')
  const canOpenCase = source === 'Case' && caseRowId !== null && onOpenResource

  const summaryItems: DescriptionsProps['items'] = [
    { key: 'knowledge-id', label: 'Knowledge ID', children: mono(upperStringValue(record, 'knowledge_id')) },
    { key: 'source', label: 'Source', children: <DescriptionValue>{knowledgeSourceTag(String(value(record, 'source') || ''))}</DescriptionValue> },
    ...(source === 'Case' ? [{
      key: 'case',
      label: 'Case',
      children: canOpenCase && caseRowId !== null ? (
        <DescriptionValue mono>
          <Button
            type="link"
            size="small"
            style={{ padding: 0, height: 'auto', fontFamily: 'inherit' }}
            onClick={() => onOpenResource?.('cases', caseRowId)}
          >
            {caseReadableId}
          </Button>
        </DescriptionValue>
      ) : mono(caseReadableId),
    }] : []),
    {
      key: 'expires-at',
      label: expiresAtState && controller ? editableLabel('Expires At') : 'Expires At',
      children: expiresAtState && controller ? (
        <EditableDescriptionValue
          state={expiresAtState}
          editor={(
            <InlineDateTimeEditor
              value={expiresAtState.value ? String(expiresAtState.value) : null}
              disabled={expiresAtState.saving}
              autoFocus={false}
              placeholder="Leave empty to never expire"
              onChange={(next) => controller.setFieldDraftValue('expires_at', next)}
              onComplete={() => controller.finishFieldEdit('expires_at')}
              onCancel={() => controller.cancelFieldDraft('expires_at')}
            />
          )}
        />
      ) : <DescriptionValue>{formatDateTime(String(value(record, 'expires_at') || ''))}</DescriptionValue>,
    },
  ]

  return (
    <div style={{ padding: '20px 20px 16px', overflow: 'hidden', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <Descriptions
        size="small"
        layout="vertical"
        colon={false}
        column={4}
        style={{ paddingTop: 4 }}
        styles={descriptionStyles}
        items={summaryItems}
      />
      <div style={{ marginTop: 16, width: '100%', minWidth: 0, display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 16, marginBottom: 16 }}>
          {titleState && controller ? (
            <div style={{ width: '100%', minWidth: 0 }}>
              <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>
                {editableLabel('Title')}
              </div>
              <div style={{ height: 32, width: '100%', minWidth: 0 }}>
                <InlineTextEditor
                  value={String(titleState.value ?? '')}
                  disabled={titleState.saving}
                  autoFocus={false}
                  onChange={(next) => controller.setFieldDraftValue('title', next)}
                  onComplete={() => controller.finishFieldEdit('title')}
                  onCancel={() => controller.cancelFieldDraft('title')}
                />
              </div>
            </div>
          ) : (
            <div style={{ minWidth: 0 }}>
              <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Title</div>
              <div style={{ ...typography.body, height: 32, display: 'flex', alignItems: 'center', color: token.colorText, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{stringValue(record, 'title')}</div>
            </div>
          )}
          {tagsState && controller ? (
            <div style={{ width: '100%', minWidth: 0 }}>
              <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>
                {editableLabel('Tags')}
              </div>
              <div style={{ height: 32, width: '100%', minWidth: 0 }}>
                <InlineTagsEditor
                  value={arrayValue(tagsState.value)}
                  disabled={tagsState.saving}
                  onStart={() => controller.startFieldEdit('tags')}
                  onChange={(next) => controller.setFieldDraftValue('tags', next)}
                  onComplete={() => controller.finishFieldEdit('tags')}
                  onCancel={() => controller.cancelFieldDraft('tags')}
                />
              </div>
            </div>
          ) : (
            <div style={{ minWidth: 0 }}>
              <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Tags</div>
              <div style={{ height: 32, display: 'flex', alignItems: 'center', minWidth: 0 }}>{renderTags(value(record, 'tags'))}</div>
            </div>
          )}
        </div>
        {bodyState && controller ? (
          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>
              {editableLabel('Body')}
            </div>
            <div style={{ flex: 1, minHeight: 0 }}>
              <InlineMarkdownEditor
                value={String(bodyState.value ?? '')}
                disabled={bodyState.saving}
                height="100%"
                onChange={(next) => controller.setFieldDraftValue('body', next)}
                onCancel={() => controller.cancelFieldDraft('body')}
              />
            </div>
          </div>
        ) : (
          <>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Body</div>
            <div style={{ width: '100%', minWidth: 0, minHeight: 0, flex: 1 }}>
              <MarkdownPreview source={String(value(record, 'body') || '')} height="100%" minHeight="100%" />
            </div>
          </>
        )}
      </div>
    </div>
  )
}
