import {useState} from 'react'
import type {SelectProps} from 'antd'
import {DatePicker, Form, Input, Modal, Select, Tag, theme, Typography} from 'antd'
import {message} from '../utils/appMessage'
import {BookOutlined} from '@ant-design/icons'
import type {Dayjs} from 'dayjs'
import client from '../api/client'
import {InlineMarkdownEditor} from './InlineFieldEditors'
import {DESCRIPTION_VALUE_HEIGHT} from './descriptionValueStyles'
import {comfortableTagProps} from '../utils/tagStyles'
import {typography} from '../utils/typography'

interface KnowledgeCreateModalProps {
  open: boolean
  onCancel: () => void
  onCreated: () => void
}

interface KnowledgeCreateValues {
  title: string
  expires_at?: Dayjs | null
  tags?: string[]
}

function apiErrorMessage(error: unknown) {
  const response = error as { response?: { data?: unknown } }
  if (response.response?.data) return JSON.stringify(response.response.data)
  return 'Failed to create knowledge'
}

const compactFormItemStyle = { marginBottom: 0 }
const fieldControlStyle = { width: '100%', height: DESCRIPTION_VALUE_HEIGHT, minWidth: 0 }
const inlineInputStyles = { input: { paddingInlineStart: 0 } }
const inlineTagSelectStyles: SelectProps['styles'] = {
  root: { paddingInlineStart: 0 },
  item: {
    background: 'rgba(22,119,255,0.16)',
    borderColor: 'rgba(22,119,255,0.35)',
    color: '#69b1ff',
  },
  itemContent: {
    color: '#69b1ff',
  },
}
const knowledgeTagRender: SelectProps['tagRender'] = ({ label, closable, onClose }) => (
  <span style={{ display: 'inline-flex', alignItems: 'center', lineHeight: 'normal' }}>
    <Tag
      {...comfortableTagProps}
      color="blue"
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

export default function KnowledgeCreateModal({ open, onCancel, onCreated }: KnowledgeCreateModalProps) {
  const { token } = theme.useToken()
  const [form] = Form.useForm<KnowledgeCreateValues>()
  const [saving, setSaving] = useState(false)
  const [body, setBody] = useState('')

  const handleAfterOpenChange = (visible: boolean) => {
    if (!visible) return
    setBody('')
    form.resetFields()
  }

  const handleOk = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      await client.post('/knowledge/', {
        title: values.title,
        expires_at: values.expires_at ? values.expires_at.toISOString() : null,
        tags: values.tags || [],
        body,
      })
      message.success('Knowledge created')
      onCreated()
    } catch (error) {
      if ((error as { errorFields?: unknown }).errorFields) return
      message.error(apiErrorMessage(error))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      title={(
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
          <BookOutlined style={{ color: token.colorPrimary }} />
          <span>Add Knowledge</span>
        </span>
      )}
      open={open}
      width="calc(100vw - 96px)"
      okText="Create"
      confirmLoading={saving}
      onOk={handleOk}
      onCancel={saving ? undefined : onCancel}
      afterOpenChange={handleAfterOpenChange}
      style={{ top: 40, maxWidth: 'none', paddingBottom: 0 }}
      styles={{
        container: { background: token.colorBgContainer, border: `1px solid ${token.colorBorder}` },
        header: { padding: '4px 8px 0', background: token.colorBgContainer },
        body: { height: 'calc(100dvh - 196px)', overflow: 'hidden', padding: '4px 4px 8px', background: token.colorBgContainer },
        footer: { padding: '10px 0px 0px', marginTop: 0, background: token.colorBgContainer },
      }}
      destroyOnHidden
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{ tags: [] }}
        disabled={saving}
        style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) minmax(220px, 280px) minmax(220px, 360px)', gap: 12 }}>
          <div style={{ marginBottom: 16 }}>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Title</div>
            <Form.Item
              name="title"
              rules={[{ required: true, whitespace: true, message: 'Title is required' }]}
              style={compactFormItemStyle}
            >
              <Input
                variant="underlined"
                styles={inlineInputStyles}
                style={fieldControlStyle}
              />
            </Form.Item>
          </div>
          <div style={{ marginBottom: 16 }}>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Expires At</div>
            <Form.Item name="expires_at" style={compactFormItemStyle}>
              <DatePicker
                showTime
                allowClear
                variant="underlined"
                placeholder="Leave empty to never expire"
                style={fieldControlStyle}
              />
            </Form.Item>
          </div>
          <div style={{ marginBottom: 16 }}>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Tags</div>
            <Form.Item name="tags" style={compactFormItemStyle}>
              <Select
                mode="tags"
                size="middle"
                variant="borderless"
                tokenSeparators={[',']}
                maxTagCount="responsive"
                tagRender={knowledgeTagRender}
                styles={inlineTagSelectStyles}
                style={fieldControlStyle}
              />
            </Form.Item>
          </div>
        </div>
        <Typography.Text style={{ ...typography.fieldLabel, color: token.colorText }}>Body</Typography.Text>
        <div style={{ marginTop: 8, width: '100%', minWidth: 0, minHeight: 0, flex: 1 }}>
          <InlineMarkdownEditor
            value={body}
            disabled={saving}
            height="100%"
            defaultMode="edit"
            onChange={setBody}
          />
        </div>
      </Form>
    </Modal>
  )
}
