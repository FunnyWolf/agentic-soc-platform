import {useState} from 'react'
import {useNavigate, useSearchParams} from 'react-router-dom'
import {BorderBeam, Button, Card, Form, Input, Segmented} from 'antd'
import {message} from '../utils/appMessage'
import {LockOutlined, UserOutlined} from '@ant-design/icons'
import type {AuthType} from '../api/auth'
import {login} from '../api/auth'
import {useAuthStore} from '../stores/auth'
import {getSafeAuthRedirectPath} from '../utils/authRedirect'
import './Login.css'

export default function Login() {
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const setAuth = useAuthStore((s) => s.setAuth)
  const nextPath = getSafeAuthRedirectPath(searchParams.get('next'))

  const onFinish = async (values: { username: string; password: string; auth_type: AuthType }) => {
    setLoading(true)
    try {
      const { data } = await login(values.username, values.password, values.auth_type)
      setAuth(data.access, data.user)
      navigate(nextPath, { replace: true })
    } catch { message.error('Invalid credentials') }
    finally { setLoading(false) }
  }

  return (
    <div className="login-page">
      <div className="login-grid" />
      <section className="login-brand-panel" aria-label="Agentic SOC Platform">
        <div className="login-brand-lockup">
          <span className="login-logo-frame">
            <img src="/favicon.svg" alt="" />
          </span>
          <div>
            <div className="login-kicker">Ready for response</div>
            <h1>Agentic SOC Platform</h1>
            <p>Security operations workspace</p>
          </div>
        </div>
        <div className="login-signal-panel" aria-hidden="true">
          <div className="login-signal-head">
            <span>Signal posture</span>
            <strong>online</strong>
          </div>
          <div className="login-signal-line wide" />
          <div className="login-signal-line" />
          <div className="login-signal-line short" />
          <div className="login-node-map">
            <span />
            <span />
            <span />
          </div>
        </div>
      </section>
      <BorderBeam
        color={[
          { color: '#1677ff', percent: 0 },
          { color: '#36cfc9', percent: 55 },
          { color: '#69b1ff', percent: 100 },
        ]}
        outset={0}
      >
        <Card className="login-card">
          <div className="login-card-header">
            <img src="/favicon.svg" alt="" />
            <div>
              <h2>Sign in</h2>
              <p>Use your platform or LDAP identity.</p>
            </div>
          </div>
          <Form className="login-form" onFinish={onFinish} size="large" initialValues={{ auth_type: 'local' }}>
            <Form.Item name="auth_type" rules={[{ required: true }]}>
              <Segmented
                className="login-auth-switch"
                options={[
                  { label: 'Platform', value: 'local' },
                  { label: 'LDAP', value: 'ldap' },
                ]}
                block
              />
            </Form.Item>
            <Form.Item name="username" rules={[{ required: true }]}>
              <Input prefix={<UserOutlined />} placeholder="Username" />
            </Form.Item>
            <Form.Item name="password" rules={[{ required: true }]}>
              <Input.Password prefix={<LockOutlined />} placeholder="Password" />
            </Form.Item>
            <Form.Item>
              <Button className="login-submit" type="primary" htmlType="submit" loading={loading} block>Log in</Button>
            </Form.Item>
          </Form>
        </Card>
      </BorderBeam>
    </div>
  )
}
