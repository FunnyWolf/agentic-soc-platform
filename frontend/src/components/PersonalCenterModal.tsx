import {useEffect, useState} from 'react'
import {Button, Col, DatePicker, Form, Input, Modal, Popconfirm, Row, Space, Switch, Table, Tabs, Tag, Typography} from 'antd'
import {message} from '../utils/appMessage'
import {ApiOutlined, CopyOutlined, DeleteOutlined, KeyOutlined, LockOutlined, ReloadOutlined, SettingOutlined, UserOutlined} from '@ant-design/icons'
import type {ColumnsType} from 'antd/es/table'
import type {Dayjs} from 'dayjs'
import client from '../api/client'
import {type ApiKey, changePassword, updateProfile} from '../api/auth'
import {useAuthStore} from '../stores/auth'
import AvatarUpload from './AvatarUpload'
import {comfortableTagProps} from '../utils/tagStyles'

interface PersonalCenterModalProps {
  open: boolean
  onClose: () => void
}

interface ApiKeyListResponse {
  results?: ApiKey[]
}

function copyText(value: string) {
  navigator.clipboard.writeText(value)
  message.success('Copied')
}

function roleColor(role?: string) {
  if (role === 'admin') return 'purple'
  if (role === 'viewer') return 'default'
  return 'blue'
}

function authTypeLabel(authType?: string) {
  return authType === 'ldap' ? 'LDAP' : 'Local'
}

export default function PersonalCenterModal({ open, onClose }: PersonalCenterModalProps) {
  const token = useAuthStore((state) => state.token)
  const user = useAuthStore((state) => state.user)
  const setAuth = useAuthStore((state) => state.setAuth)
  const [profileForm] = Form.useForm()
  const [settingsForm] = Form.useForm()
  const [passwordForm] = Form.useForm()
  const [apiKeyForm] = Form.useForm()
  const [savingProfile, setSavingProfile] = useState(false)
  const [savingSettings, setSavingSettings] = useState(false)
  const [changingPassword, setChangingPassword] = useState(false)
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([])
  const [apiKeysLoading, setApiKeysLoading] = useState(false)
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState(false)

  useEffect(() => {
    if (!open || !user) return
    profileForm.setFieldsValue(user)
    settingsForm.setFieldsValue({
      notify_on_playbook_completion: user.notify_on_playbook_completion ?? true,
      notify_on_case_assignment: user.notify_on_case_assignment ?? true,
    })
  }, [open, profileForm, settingsForm, user])

  const loadApiKeys = async () => {
    setApiKeysLoading(true)
    try {
      const { data } = await client.get<ApiKey[] | ApiKeyListResponse>('/auth/api-keys/')
      setApiKeys(Array.isArray(data) ? data : data.results || [])
    } catch {
      message.error('Failed to load API keys')
    } finally {
      setApiKeysLoading(false)
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (open) loadApiKeys()
  }, [open])

  const saveProfile = async () => {
    if (!token) return
    setSavingProfile(true)
    try {
      const values = await profileForm.validateFields()
      const { data } = await updateProfile(values)
      setAuth(token, data)
      message.success('Profile updated')
    } catch (error: unknown) {
      const response = error as { response?: { data?: unknown } }
      if (response.response?.data) message.error(JSON.stringify(response.response.data))
    } finally {
      setSavingProfile(false)
    }
  }

  const saveSettings = async () => {
    if (!token) return
    setSavingSettings(true)
    try {
      const values = await settingsForm.validateFields()
      const { data } = await updateProfile(values)
      setAuth(token, data)
      message.success('Settings updated')
    } catch (error: unknown) {
      const response = error as { response?: { data?: unknown } }
      if (response.response?.data) message.error(JSON.stringify(response.response.data))
    } finally {
      setSavingSettings(false)
    }
  }

  const savePassword = async () => {
    setChangingPassword(true)
    try {
      const values = await passwordForm.validateFields()
      if (values.new_password !== values.confirm) {
        message.error('Passwords do not match')
        return
      }
      await changePassword(values.old_password, values.new_password)
      passwordForm.resetFields()
      message.success('Password changed')
    } catch (error: unknown) {
      const response = error as { response?: { data?: { detail?: string } } }
      message.error(response.response?.data?.detail || 'Failed to change password')
    } finally {
      setChangingPassword(false)
    }
  }

  const createApiKey = async () => {
    try {
      const values = await apiKeyForm.validateFields()
      await client.post('/auth/api-keys/', {
        name: values.name,
        expires_at: values.expires_at ? (values.expires_at as Dayjs).toISOString() : null,
      })
      apiKeyForm.resetFields()
      setApiKeyModalOpen(false)
      message.success('API key created')
      loadApiKeys()
    } catch (error: unknown) {
      const response = error as { response?: { data?: unknown } }
      if (response.response?.data) message.error(JSON.stringify(response.response.data))
    }
  }

  const refreshApiKey = async (id: number) => {
    try {
      await client.post(`/auth/api-keys/${id}/refresh/`)
      message.success('API key refreshed')
      loadApiKeys()
    } catch {
      message.error('Failed to refresh API key')
    }
  }

  const deleteApiKey = async (id: number) => {
    try {
      await client.delete(`/auth/api-keys/${id}/`)
      message.success('API key deleted')
      loadApiKeys()
    } catch {
      message.error('Failed to delete API key')
    }
  }

  const apiKeyColumns: ColumnsType<ApiKey> = [
    { title: 'Name', dataIndex: 'name', width: 180 },
    {
      title: 'Key',
      dataIndex: 'key',
      render: (value: string) => <Input.Password value={value} readOnly  />,
    },
    { title: 'Expires At', dataIndex: 'expires_at', width: 160, render: (value) => value ? new Date(String(value)).toLocaleString() : 'Never' },
    { title: 'Last Used', dataIndex: 'last_used_at', width: 160, render: (value) => value ? new Date(String(value)).toLocaleString() : '—' },
    {
      title: 'Actions',
      key: 'actions',
      width: 120,
      render: (_value, record) => (
        <Space>
          <Button size="small" type="text" icon={<CopyOutlined />} onClick={() => copyText(record.key)} />
          <Popconfirm title="Refresh API key?" onConfirm={() => refreshApiKey(record.id)}>
            <Button size="small" type="text" icon={<ReloadOutlined />} />
          </Popconfirm>
          <Popconfirm title="Delete API key?" okButtonProps={{ danger: true }} onConfirm={() => deleteApiKey(record.id)}>
            <Button size="small" type="text" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const items = [
    {
      key: 'profile',
      label: <span><UserOutlined /> Profile</span>,
      children: (
        <Space vertical size="middle" style={{ width: '100%' }}>
          {user && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, paddingBottom: 8 }}>
              <AvatarUpload
                user={user}
                endpoint="/auth/avatar/"
                onChange={(nextUser) => {
                  if (token) setAuth(token, nextUser)
                }}
              />
              <Space vertical size={6}>
                <Typography.Title level={4} style={{ margin: 0 }}>{user.username}</Typography.Title>
                <Space size={6}>
                  <Tag {...comfortableTagProps} color={roleColor(user.role)}>{user.role.toUpperCase()}</Tag>
                  <Tag {...comfortableTagProps} color={user.auth_type === 'ldap' ? 'geekblue' : 'green'}>{authTypeLabel(user.auth_type)}</Tag>
                </Space>
              </Space>
            </div>
          )}
          <Form form={profileForm} layout="vertical">
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="email" label="Email" rules={[{ type: 'email' }]}><Input /></Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="mobile_phone" label="Mobile Phone"><Input /></Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="first_name" label="First Name"><Input /></Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="last_name" label="Last Name"><Input /></Form.Item>
              </Col>
            </Row>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button type="primary" loading={savingProfile} onClick={saveProfile}>Save</Button>
            </div>
          </Form>
        </Space>
      ),
    },
    {
      key: 'settings',
      label: <span><SettingOutlined /> Settings</span>,
      children: (
        <Space vertical size="middle" style={{ width: '100%' }}>
          <Typography.Title level={5} style={{ margin: 0 }}>Notification Preferences</Typography.Title>
          <Form form={settingsForm} layout="vertical">
            <Form.Item
              name="notify_on_playbook_completion"
              label="Notify me when my Playbook runs finish"
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
            <Form.Item
              name="notify_on_case_assignment"
              label="Notify me when a Case is assigned to me"
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button type="primary" loading={savingSettings} onClick={saveSettings}>Save</Button>
            </div>
          </Form>
        </Space>
      ),
    },
    user?.auth_type === 'local' ? {
      key: 'password',
      label: <span><LockOutlined /> Password</span>,
      children: (
        <Form form={passwordForm} layout="vertical">
          <Form.Item name="old_password" label="Current Password" rules={[{ required: true }]}><Input.Password /></Form.Item>
          <Form.Item name="new_password" label="New Password" rules={[{ required: true, min: 8 }]}><Input.Password /></Form.Item>
          <Form.Item name="confirm" label="Confirm Password" rules={[{ required: true }]}><Input.Password /></Form.Item>
          <Button type="primary" loading={changingPassword} onClick={savePassword}>Change Password</Button>
        </Form>
      ),
    } : null,
    {
      key: 'api-keys',
      label: <span><ApiOutlined /> API Keys</span>,
      children: (
        <Space vertical style={{ width: '100%' }} size="middle">
        <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
          <Button type="primary" icon={<KeyOutlined />} onClick={() => setApiKeyModalOpen(true)} />
        </Space>
          <Table<ApiKey>
            size="small"
            rowKey="id"
            columns={apiKeyColumns}
            dataSource={apiKeys}
            loading={apiKeysLoading}
            pagination={false}
          />
        </Space>
      ),
    },
  ].filter((item): item is NonNullable<typeof item> => Boolean(item))

  return (
    <>
      <Modal
        open={open}
        onCancel={onClose}
        footer={null}
        width={1100}
        destroyOnHidden
        className="personal-modal"
      >
        <Tabs
          items={items}
          className="personal-modal-tabs"
        />
      </Modal>
      <Modal title="Create API Key" open={apiKeyModalOpen} onOk={createApiKey} onCancel={() => setApiKeyModalOpen(false)} destroyOnHidden>
        <Form form={apiKeyForm} layout="vertical">
          <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="expires_at" label="Expires At"><DatePicker showTime placeholder="Leave empty to never expire" style={{ width: '100%' }} /></Form.Item>
        </Form>
      </Modal>
    </>
  )
}
