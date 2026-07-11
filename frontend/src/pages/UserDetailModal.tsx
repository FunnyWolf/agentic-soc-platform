import {useEffect, useState} from 'react'
import {Button, Col, Divider, Form, Input, Modal, Row, Select, Space, theme, Typography} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'
import type {AuthUser} from '../stores/auth'
import AvatarUpload from '../components/AvatarUpload'

interface UserDetailModalProps {
  userId: string | number | null
  open: boolean
  onClose: () => void
  onSaved: () => void
}

interface UserDetailValues {
  email?: string
  first_name?: string
  last_name?: string
  mobile_phone?: string
  role?: 'user' | 'viewer'
}

export default function UserDetailModal({ userId, open, onClose, onSaved }: UserDetailModalProps) {
  const { token } = theme.useToken()
  const [form] = Form.useForm<UserDetailValues>()
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!open || userId === null) return

    client.get<AuthUser>(`/auth/users/${userId}/`)
      .then(({ data }) => {
        setUser(data)
        form.setFieldsValue({
          email: data.email,
          first_name: data.first_name,
          last_name: data.last_name,
          mobile_phone: data.mobile_phone,
          role: data.role === 'admin' ? undefined : data.role,
        })
      })
      .catch(() => {
        message.error('Failed to load user')
        onClose()
      })
      .finally(() => setLoading(false))
  }, [form, onClose, open, userId])

  const save = async () => {
    if (!userId) return
    setSaving(true)
    try {
      const values = await form.validateFields()
      const payload = user?.role === 'admin' ? { ...values, role: undefined } : values
      const { data } = await client.patch<AuthUser>(`/auth/users/${userId}/`, payload)
      setUser(data)
      message.success('User updated')
      onSaved()
    } catch (error: unknown) {
      const response = error as { response?: { data?: unknown } }
      if (response.response?.data) message.error(JSON.stringify(response.response.data))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      title={user ? `User: ${user.username}` : 'User Detail'}
      open={open}
      onCancel={onClose}
      footer={(
        <Space>
          <Button onClick={onClose}>Close</Button>
          <Button type="primary" loading={saving} onClick={save}>Save</Button>
        </Space>
      )}
      width={720}
      styles={{
        container: { background: token.colorBgContainer, border: `1px solid ${token.colorBorder}` },
        header: { background: token.colorBgContainer },
        body: { background: token.colorBgContainer },
        footer: { background: token.colorBgContainer },
      }}
      destroyOnHidden
      afterOpenChange={(nextOpen) => {
        if (nextOpen) {
          if (userId !== null) setLoading(true)
          return
        }
        setUser(null)
        form.resetFields()
      }}
    >
      <Form form={form} layout="vertical" disabled={loading} style={{ paddingTop: 8 }}>
        <Row gutter={16}>
          <Col span={20}>
            <Form.Item label="Username"><Input value={user?.username} disabled /></Form.Item>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item label="Authentication Type"><Input value={user?.auth_type === 'ldap' ? 'LDAP' : 'Local Password'} disabled /></Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="role" label="Role">
                  <Select
                    disabled={user?.role === 'admin'}
                    placeholder={user?.role === 'admin' ? 'Admin' : undefined}
                    options={[
                      { label: 'User', value: 'user' },
                      { label: 'Viewer', value: 'viewer' },
                    ]}
                  />
                </Form.Item>
              </Col>
            </Row>
          </Col>
          <Col span={4}>
            {user && (
              <Form.Item label={<div style={{ width: '100%', textAlign: 'center' }}>Avatar</div>}>
                <div style={{ minHeight: 92, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <AvatarUpload
                    user={user}
                    endpoint={`/auth/users/${user.id}/avatar/`}
                    disabled={loading}
                    onChange={(nextUser) => {
                      setUser(nextUser)
                      onSaved()
                    }}
                  />
                </div>
              </Form.Item>
            )}
          </Col>
        </Row>
        <Typography.Text strong>Profile</Typography.Text>
        <Divider style={{ margin: '8px 0 16px' }} />
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
      </Form>
    </Modal>
  )
}
