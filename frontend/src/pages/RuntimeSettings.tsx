import {useCallback, useEffect, useState} from 'react'
import {Button, Card, Col, Divider, Form, InputNumber, Row, Select, Space, Tooltip, Typography} from 'antd'
import {message} from '../utils/appMessage'
import {QuestionCircleOutlined} from '@ant-design/icons'
import client from '../api/client'

interface RuntimeConfig {
  prompt_language: 'en' | 'zh'
  stream_maxlen: number
  updated_at?: string
}

function initialValues(): RuntimeConfig {
  return {
    prompt_language: 'en',
    stream_maxlen: 10000,
  }
}

function apiErrorMessage(error: unknown, fallback: string) {
  const response = error as { response?: { data?: unknown } }
  const data = response.response?.data
  if (!data) return fallback
  if (typeof data === 'string') return data
  if (typeof data === 'object') {
    const detail = (data as { detail?: unknown }).detail
    if (typeof detail === 'string') return detail
    return JSON.stringify(data)
  }
  return fallback
}

function helpLabel(label: string, help: string) {
  return (
    <span>
      {label}
      <Tooltip title={help}>
        <QuestionCircleOutlined style={{ marginLeft: 6, color: 'rgba(255,255,255,0.45)' }} />
      </Tooltip>
    </span>
  )
}

export default function RuntimeSettings() {
  const [form] = Form.useForm<RuntimeConfig>()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await client.get<RuntimeConfig>('/settings/runtime/')
      form.setFieldsValue({ ...initialValues(), ...data })
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load Runtime configuration'))
    } finally {
      setLoading(false)
    }
  }, [form])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConfig()
  }, [loadConfig])

  const saveConfig = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      const { data } = await client.patch<RuntimeConfig>('/settings/runtime/', values)
      form.setFieldsValue({ ...initialValues(), ...data })
      message.success('Runtime configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save Runtime configuration'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Card title="Runtime" loading={loading}>
        <Form form={form} layout="vertical" initialValues={initialValues()} style={{ maxWidth: 920 }}>
          <Typography.Text strong>Prompt</Typography.Text>
          <Divider style={{ margin: '8px 0 16px' }} />
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="prompt_language"
                label={helpLabel('Prompt Language', 'Selects the prompt file language used by agentic analysis and extraction prompts.')}
                rules={[{ required: true }]}
              >
                <Select options={[
                  { label: 'English', value: 'en' },
                  { label: '中文', value: 'zh' },
                ]} />
              </Form.Item>
            </Col>
          </Row>

          <Typography.Text strong>Stream Runtime</Typography.Text>
          <Divider style={{ margin: '8px 0 16px' }} />
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="stream_maxlen"
                label={helpLabel('Stream Maxlen', 'Approximate maximum length retained for Redis Streams written by webhook alert ingestion. ELK action processing uses the same webhook write path.')}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={10000000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          <Space>
            <Button type="primary" onClick={saveConfig} loading={saving}>Save</Button>
          </Space>
        </Form>
      </Card>
    </div>
  )
}
