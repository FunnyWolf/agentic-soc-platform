import {useCallback, useEffect, useState} from 'react'
import {Button, Card, Form, Input, InputNumber, message, Space, Switch, Tabs} from 'antd'
import {ChartNetwork, SatelliteDish} from 'lucide-react'
import client from '../api/client'

interface AlienVaultOTXConfig {
  enabled: boolean
  api_key: string
  api_key_configured: boolean
  base_url: string
  proxy: string
  timeout_seconds: number
  updated_at?: string
}

interface OpenCTIConfig {
  enabled: boolean
  url: string
  token: string
  token_configured: boolean
  ssl_verify: boolean
  proxy: string
  timeout_seconds: number
  updated_at?: string
}

interface ProviderTestResult {
  success: boolean
  detail: string
  response_preview?: string
}

function initialOTXValues(): AlienVaultOTXConfig {
  return {
    enabled: false,
    api_key: '',
    api_key_configured: false,
    base_url: 'https://otx.alienvault.com/api/v1',
    proxy: '',
    timeout_seconds: 10,
  }
}

function initialOpenCTIValues(): OpenCTIConfig {
  return {
    enabled: false,
    url: 'http://localhost:8080',
    token: '',
    token_configured: false,
    ssl_verify: false,
    proxy: '',
    timeout_seconds: 30,
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

export default function ThreatIntelligenceSettings() {
  const [otxForm] = Form.useForm<AlienVaultOTXConfig>()
  const [openctiForm] = Form.useForm<OpenCTIConfig>()
  const [loading, setLoading] = useState(false)
  const [savingProvider, setSavingProvider] = useState<string | null>(null)
  const [testingProvider, setTestingProvider] = useState<string | null>(null)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      const [otxResponse, openctiResponse] = await Promise.all([
        client.get<AlienVaultOTXConfig>('/settings/threat-intel/otx/', {
          params: { reveal_secrets: true },
        }),
        client.get<OpenCTIConfig>('/settings/threat-intel/opencti/', {
          params: { reveal_secrets: true },
        }),
      ])
      otxForm.setFieldsValue({ ...initialOTXValues(), ...otxResponse.data })
      openctiForm.setFieldsValue({ ...initialOpenCTIValues(), ...openctiResponse.data })
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load threat intelligence configuration'))
    } finally {
      setLoading(false)
    }
  }, [openctiForm, otxForm])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConfig()
  }, [loadConfig])

  const saveOTXConfig = async () => {
    setSavingProvider('otx')
    try {
      const values = await otxForm.validateFields()
      const { data } = await client.patch<AlienVaultOTXConfig>('/settings/threat-intel/otx/', {
        ...values,
        api_key: values.api_key || '',
        proxy: values.proxy || '',
      })
      otxForm.setFieldsValue({ ...initialOTXValues(), ...data, api_key: values.api_key || '' })
      message.success('AlienVault OTX configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save AlienVault OTX configuration'))
    } finally {
      setSavingProvider(null)
    }
  }

  const testOTXConfig = async () => {
    setTestingProvider('otx')
    try {
      const values = await otxForm.validateFields()
      const { data } = await client.post<ProviderTestResult>('/settings/threat-intel/otx/test/', {
        ...values,
        api_key: values.api_key || '',
        proxy: values.proxy || '',
      })
      if (data.success) message.success(data.detail)
      else message.error(data.detail)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test AlienVault OTX configuration'))
    } finally {
      setTestingProvider(null)
    }
  }

  const saveOpenCTIConfig = async () => {
    setSavingProvider('opencti')
    try {
      const values = await openctiForm.validateFields()
      const { data } = await client.patch<OpenCTIConfig>('/settings/threat-intel/opencti/', {
        ...values,
        token: values.token || '',
        proxy: values.proxy || '',
      })
      openctiForm.setFieldsValue({ ...initialOpenCTIValues(), ...data, token: values.token || '' })
      message.success('OpenCTI configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save OpenCTI configuration'))
    } finally {
      setSavingProvider(null)
    }
  }

  const testOpenCTIConfig = async () => {
    setTestingProvider('opencti')
    try {
      const values = await openctiForm.validateFields()
      const { data } = await client.post<ProviderTestResult>('/settings/threat-intel/opencti/test/', {
        ...values,
        token: values.token || '',
        proxy: values.proxy || '',
      })
      if (data.success) message.success(data.detail)
      else message.error(data.detail)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test OpenCTI configuration'))
    } finally {
      setTestingProvider(null)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Tabs
        items={[
          {
            key: 'otx',
            label: 'AlienVault OTX',
            icon: <SatelliteDish size={16} />,
            children: (
              <Card loading={loading}>
                <Form form={otxForm} layout="vertical" initialValues={initialOTXValues()} style={{ maxWidth: 760 }}>
                  <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item name="base_url" label="Base URL" rules={[{ required: true }, { type: 'url' }]}>
                    <Input placeholder="https://otx.alienvault.com/api/v1" />
                  </Form.Item>
                  <Form.Item name="api_key" label="API Key" rules={[{ required: true, message: 'API key is required' }]}>
                    <Input.Password autoComplete="new-password" />
                  </Form.Item>
                  <Form.Item name="proxy" label="Proxy">
                    <Input placeholder="http://127.0.0.1:7890" />
                  </Form.Item>
                  <Form.Item name="timeout_seconds" label="Timeout Seconds" rules={[{ required: true }]}>
                    <InputNumber min={1} max={300} style={{ width: 180 }} />
                  </Form.Item>
                  <Space>
                    <Button onClick={testOTXConfig} loading={testingProvider === 'otx'}>Test</Button>
                    <Button type="primary" onClick={saveOTXConfig} loading={savingProvider === 'otx'}>Save</Button>
                  </Space>
                </Form>
              </Card>
            ),
          },
          {
            key: 'opencti',
            label: 'OpenCTI',
            icon: <ChartNetwork size={16} />,
            children: (
              <Card loading={loading}>
                <Form form={openctiForm} layout="vertical" initialValues={initialOpenCTIValues()} style={{ maxWidth: 760 }}>
                  <Form.Item name="enabled" label="Enabled" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item name="url" label="Base URL" rules={[{ required: true }, { type: 'url' }]}>
                    <Input placeholder="http://localhost:8080" />
                  </Form.Item>
                  <Form.Item name="token" label="API Token" rules={[{ required: true, message: 'API token is required' }]}>
                    <Input.Password autoComplete="new-password" />
                  </Form.Item>
                  <Form.Item name="ssl_verify" label="SSL Verify" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item name="proxy" label="Proxy">
                    <Input placeholder="http://127.0.0.1:7890" />
                  </Form.Item>
                  <Form.Item name="timeout_seconds" label="Timeout Seconds" rules={[{ required: true }]}>
                    <InputNumber min={1} max={300} style={{ width: 180 }} />
                  </Form.Item>
                  <Space>
                    <Button onClick={testOpenCTIConfig} loading={testingProvider === 'opencti'}>Test</Button>
                    <Button type="primary" onClick={saveOpenCTIConfig} loading={savingProvider === 'opencti'}>Save</Button>
                  </Space>
                </Form>
              </Card>
            ),
          },
        ]}
      />
    </div>
  )
}
