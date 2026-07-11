import {useCallback, useEffect, useRef, useState} from 'react'
import {Alert, Button, Spin} from 'antd'
import {ReloadOutlined} from '@ant-design/icons'
import client from '../api/client'
import InvestigationReportView from './InvestigationReportView'

interface CaseInvestigationViewProps {
  caseId: string
}

interface CaseInvestigationResponse {
  investigation_report_ai_json: unknown
}

function errorMessage(error: unknown) {
  const data = (error as { response?: { data?: unknown } }).response?.data
  if (typeof data === 'string') return data
  if (data && typeof data === 'object' && 'detail' in data) {
    return String((data as { detail?: unknown }).detail || 'Failed to load investigation report')
  }
  return 'Failed to load investigation report'
}

export default function CaseInvestigationView({ caseId }: CaseInvestigationViewProps) {
  const [value, setValue] = useState<unknown>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const requestIdRef = useRef(0)

  const loadReport = useCallback(() => {
    if (!caseId) return
    const requestId = requestIdRef.current + 1
    requestIdRef.current = requestId
    setLoading(true)
    setError('')

    client.get<CaseInvestigationResponse>(`/cases/${encodeURIComponent(caseId)}/investigation/`)
      .then(({ data }) => {
        if (requestId !== requestIdRef.current) return
        setValue(data.investigation_report_ai_json || '')
      })
      .catch((loadError) => {
        if (requestId !== requestIdRef.current) return
        setValue('')
        setError(errorMessage(loadError))
      })
      .finally(() => {
        if (requestId === requestIdRef.current) setLoading(false)
      })
  }, [caseId])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadReport()
    return () => {
      requestIdRef.current += 1
    }
  }, [loadReport])

  if (loading) return <Spin style={{ margin: 32 }} />
  if (error) {
    return (
      <div style={{ padding: 20 }}>
        <Alert
          type="error"
          showIcon
          title={error}
          action={<Button size="small" icon={<ReloadOutlined />} onClick={loadReport}>Retry</Button>}
        />
      </div>
    )
  }

  return <InvestigationReportView value={value} />
}
