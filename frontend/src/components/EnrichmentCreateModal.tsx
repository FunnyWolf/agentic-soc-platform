import {useEffect, useState} from 'react'
import {ExperimentOutlined} from '@ant-design/icons'
import {Form, Input, Modal, Select, theme} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'
import {fetchResourceMetadata} from '../api/metadata'
import type {ChoiceOption} from '../types/records'
import {DESCRIPTION_VALUE_HEIGHT} from './descriptionValueStyles'
import {typography} from '../utils/typography'

export type EnrichmentTargetType = 'case' | 'alert' | 'artifact'

interface EnrichmentCreateModalProps {
  open: boolean
  targetType: EnrichmentTargetType
  targetId: string
  onCancel: () => void
  onCreated: () => void
}

interface EnrichmentCreateValues {
  type?: string
  name?: string
  desc?: string
  uid?: string
  value?: string
}

function apiErrorMessage(error: unknown) {
  const response = error as { response?: { data?: unknown } }
  if (response.response?.data) return JSON.stringify(response.response.data)
  return 'Failed to create enrichment'
}

const compactFormItemStyle = { marginBottom: 0 }
const fieldControlStyle = { width: '100%', height: DESCRIPTION_VALUE_HEIGHT, minWidth: 0 }
const inlineInputStyles = { input: { paddingInlineStart: 0 } }
const inlineTextAreaStyles = { textarea: { paddingInlineStart: 0 } }

export default function EnrichmentCreateModal({ open, targetType, targetId, onCancel, onCreated }: EnrichmentCreateModalProps) {
  const { token } = theme.useToken()
  const [form] = Form.useForm<EnrichmentCreateValues>()
  const [saving, setSaving] = useState(false)
  const [typeOptions, setTypeOptions] = useState<ChoiceOption[]>([])

  useEffect(() => {
    if (!open) return
    fetchResourceMetadata()
      .then((metadata) => setTypeOptions(metadata.resources.enrichments?.choices?.type || []))
      .catch(() => setTypeOptions([]))
  }, [open])

  const handleAfterOpenChange = (visible: boolean) => {
    if (!visible) return
    form.resetFields()
  }

  const handleOk = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      await client.post('/enrichments/', {
        provider: 'MANUAL',
        type: values.type || undefined,
        name: values.name || '',
        desc: values.desc || '',
        uid: values.uid || '',
        value: values.value || '',
        data: {},
        [targetType]: targetId,
      })
      message.success('Enrichment created')
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
          <ExperimentOutlined style={{ color: token.colorPrimary }} />
          <span>Add Enrichment</span>
        </span>
      )}
      open={open}
      width={760}
      okText="Create"
      confirmLoading={saving}
      onOk={handleOk}
      onCancel={saving ? undefined : onCancel}
      afterOpenChange={handleAfterOpenChange}
      style={{ top: 40, paddingBottom: 0 }}
      styles={{
        container: { background: token.colorBgContainer, border: `1px solid ${token.colorBorder}` },
        header: { padding: '4px 8px 0', background: token.colorBgContainer },
        body: { padding: '4px 4px 8px', background: token.colorBgContainer },
        footer: { padding: '10px 0px 0px', marginTop: 0, background: token.colorBgContainer },
      }}
      destroyOnHidden
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{ type: 'Other' }}
        disabled={saving}
      >
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Type</div>
            <Form.Item name="type" style={compactFormItemStyle}>
              <Select
                allowClear
                showSearch
                variant="borderless"
                options={typeOptions}
                style={fieldControlStyle}
              />
            </Form.Item>
          </div>
          <div>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Name</div>
            <Form.Item name="name" style={compactFormItemStyle}>
              <Input variant="underlined" styles={inlineInputStyles} style={fieldControlStyle} />
            </Form.Item>
          </div>
          <div>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>UID</div>
            <Form.Item name="uid" style={compactFormItemStyle}>
              <Input variant="underlined" styles={inlineInputStyles} style={fieldControlStyle} />
            </Form.Item>
          </div>
          <div>
            <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Value</div>
            <Form.Item name="value" style={compactFormItemStyle}>
              <Input variant="underlined" styles={inlineInputStyles} style={fieldControlStyle} />
            </Form.Item>
          </div>
        </div>
        <div style={{ marginTop: 16 }}>
          <div style={{ ...typography.fieldLabel, color: token.colorText, marginBottom: 8 }}>Description</div>
          <Form.Item name="desc" style={compactFormItemStyle}>
            <Input.TextArea
              variant="underlined"
              autoSize={{ minRows: 4, maxRows: 8 }}
              styles={inlineTextAreaStyles}
            />
          </Form.Item>
        </div>
      </Form>
    </Modal>
  )
}
