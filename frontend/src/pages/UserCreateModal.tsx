import {Col, Divider, Form, Input, Modal, Row, Select, Typography} from 'antd'
import {message} from '../utils/appMessage'
import client from '../api/client'
import type {AuthType, UserMutationResponse} from '../api/auth'

interface UserCreateModalProps {
  open: boolean
  onClose: () => void
  onCreated: (response: UserMutationResponse) => void
}

interface UserCreateValues {
  username: string
  auth_type: AuthType
  role: 'user' | 'viewer'
  email?: string
  first_name?: string
  last_name?: string
  mobile_phone?: string
}

export default function UserCreateModal({ open, onClose, onCreated }: UserCreateModalProps) {
  const [form] = Form.useForm<UserCreateValues>()

  const onOk = async () => {
    try {
      const values = await form.validateFields()
      const { data } = await client.post<UserMutationResponse>('/auth/users/', values)
      form.resetFields()
      onCreated(data)
    } catch (error: unknown) {
      const response = error as { response?: { data?: unknown } }
      if (response.response?.data) message.error(JSON.stringify(response.response.data))
    }
  }

  return (
    <Modal title="Create User" open={open} onOk={onOk} onCancel={onClose} okText="Create" width={720} destroyOnHidden>
      <Form form={form} layout="vertical" initialValues={{ auth_type: 'local', role: 'user' }} style={{ paddingTop: 8 }}>
        <Form.Item name="username" label="Username" rules={[{ required: true }]}><Input /></Form.Item>
        <Row gutter={16}>
          <Col span={12}>
            <Form.Item name="auth_type" label="Authentication Type" rules={[{ required: true }]}>
              <Select options={[
                { label: 'Local Password', value: 'local' },
                { label: 'LDAP', value: 'ldap' },
              ]} />
            </Form.Item>
          </Col>
          <Col span={12}>
            <Form.Item name="role" label="Role" rules={[{ required: true }]}>
              <Select options={[
                { label: 'User', value: 'user' },
                { label: 'Viewer', value: 'viewer' },
              ]} />
            </Form.Item>
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
