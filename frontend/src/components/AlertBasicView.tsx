import {Button, Descriptions} from 'antd'
import DetailSectionDivider from './DetailSectionDivider'
import JsonViewer from './JsonViewer'
import {alertActionTag, alertAnalyticTypeTag, alertDispositionTag, choiceTag, emptyValue, formatDateTime, productCategoryTag, severityTag, statusTag} from '../utils/recordDisplay'
import TagList from './TagList'
import {monoTextStyle} from '../utils/typography'

type RecordRow = Record<string, unknown>

interface AlertBasicViewProps {
  record: RecordRow
  onOpenResource?: (resourceKey: string, rowId: string | number) => void
}

const value = (record: RecordRow, key: string) => record[key]
const stringValue = (record: RecordRow, key: string) => emptyValue(value(record, key))
const upperStringValue = (record: RecordRow, key: string) => {
  const displayValue = stringValue(record, key)
  return displayValue === '—' ? displayValue : displayValue.toUpperCase()
}
const mono = (children: string) => <span style={monoTextStyle}>{children}</span>
const block = (children: string) => <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{children}</div>
function Section({ title, children, showTitle = true }: { title: string; children: React.ReactNode; showTitle?: boolean }) {
  return (
    <div style={{ marginTop: showTitle ? 16 : 0 }}>
      {showTitle && (
        <DetailSectionDivider title={title} />
      )}
      <Descriptions
        size="small"
        layout="vertical"
        colon={false}
        column={4}
      >
        {children}
      </Descriptions>
    </div>
  )
}

export default function AlertBasicView({ record, onOpenResource }: AlertBasicViewProps) {
  const caseRowId = value(record, 'case_id') as string | number | null | undefined
  const caseReadableId = upperStringValue(record, 'case_readable_id')
  const caseDisplayId = caseReadableId !== '—'
    ? caseReadableId
    : upperStringValue(record, 'case_id')
  const canOpenCase = Boolean(caseRowId !== null && caseRowId !== undefined && onOpenResource)

  return (
    <div style={{ padding: '20px 20px 16px', overflow: 'auto', height: '100%', boxSizing: 'border-box' }}>
      <Section title="Basic" showTitle={false}>
        <Descriptions.Item label="Alert ID">{mono(upperStringValue(record, 'alert_id'))}</Descriptions.Item>
        <Descriptions.Item label="Case">
          {canOpenCase && caseRowId !== null && caseRowId !== undefined ? (
            <Button
              type="link"
              size="small"
              style={{ padding: 0, height: 'auto' }}
              onClick={() => onOpenResource?.('cases', caseRowId)}
            >
              {caseDisplayId}
            </Button>
          ) : caseDisplayId}
        </Descriptions.Item>
        <Descriptions.Item label="First Seen">{formatDateTime(String(value(record, 'first_seen_time') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Last Seen">{formatDateTime(String(value(record, 'last_seen_time') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Severity">{severityTag(String(value(record, 'severity') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Confidence">{severityTag(String(value(record, 'confidence') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Impact">{severityTag(String(value(record, 'impact') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Risk Level">{severityTag(String(value(record, 'risk_level') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Labels" span={4}><TagList items={value(record, 'labels')} /></Descriptions.Item>
        <Descriptions.Item label="Description" span={4}>{block(stringValue(record, 'desc'))}</Descriptions.Item>
      </Section>

      <Section title="Correlation">
        <Descriptions.Item label="Rule ID">{mono(stringValue(record, 'rule_id'))}</Descriptions.Item>
        <Descriptions.Item label="Rule Name">{stringValue(record, 'rule_name')}</Descriptions.Item>
        <Descriptions.Item label="Correlation UID" span="filled">{mono(stringValue(record, 'correlation_uid'))}</Descriptions.Item>
      </Section>

      <Section title="MITRE ATT&CK and ATLAS">
        <Descriptions.Item label="Tactic">{stringValue(record, 'tactic')}</Descriptions.Item>
        <Descriptions.Item label="Technique">{stringValue(record, 'technique')}</Descriptions.Item>
        <Descriptions.Item label="Sub-technique">{stringValue(record, 'sub_technique')}</Descriptions.Item>
        <Descriptions.Item label="Mitigation">{stringValue(record, 'mitigation')}</Descriptions.Item>
      </Section>

      <Section title="Status & Disposition & Action & Remediation">
        <Descriptions.Item label="Disposition">{alertDispositionTag(String(value(record, 'disposition') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Action">{alertActionTag(String(value(record, 'action') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Status" span="filled">{statusTag(String(value(record, 'status') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Status Detail" span={4}>{block(stringValue(record, 'status_detail'))}</Descriptions.Item>
        <Descriptions.Item label="Remediation" span={4}>{block(stringValue(record, 'remediation'))}</Descriptions.Item>
      </Section>

      <Section title="Product & Source">
        <Descriptions.Item label="Product Category">{productCategoryTag(String(value(record, 'product_category') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Product Vendor">{choiceTag(String(value(record, 'product_vendor') || ''), 'cyan')}</Descriptions.Item>
        <Descriptions.Item label="Product Name">{choiceTag(String(value(record, 'product_name') || ''), 'cyan')}</Descriptions.Item>
        <Descriptions.Item label="Product Feature">{choiceTag(String(value(record, 'product_feature') || ''), 'cyan')}</Descriptions.Item>
        <Descriptions.Item label="Source URL">{mono(stringValue(record, 'src_url'))}</Descriptions.Item>
        <Descriptions.Item label="Source UID">{mono(stringValue(record, 'source_uid'))}</Descriptions.Item>
        <Descriptions.Item label="Data Sources" span={2}><TagList items={value(record, 'data_sources')} color="cyan" /></Descriptions.Item>
      </Section>

      <Section title="Analytic & Policy">
        <Descriptions.Item label="Analytic Name">{stringValue(record, 'analytic_name')}</Descriptions.Item>
        <Descriptions.Item label="Analytic Type">{alertAnalyticTypeTag(String(value(record, 'analytic_type') || ''))}</Descriptions.Item>
        <Descriptions.Item label="Analytic State" span="filled">{choiceTag(String(value(record, 'analytic_state') || ''), 'green')}</Descriptions.Item>
        <Descriptions.Item label="Analytic Description" span={4}>{block(stringValue(record, 'analytic_desc'))}</Descriptions.Item>
        <Descriptions.Item label="Policy Name">{stringValue(record, 'policy_name')}</Descriptions.Item>
        <Descriptions.Item label="Policy Type">{choiceTag(String(value(record, 'policy_type') || ''), 'volcano')}</Descriptions.Item>
        <Descriptions.Item label="Policy Description" span={2}>{stringValue(record, 'policy_desc')}</Descriptions.Item>
      </Section>

      <Section title="Raw / Unmapped">
        <Descriptions.Item label="Raw Log" span={2}>
          <JsonViewer value={record.raw_data} maxHeight="none" />
        </Descriptions.Item>
        <Descriptions.Item label="Unmapped" span={2}>
          <JsonViewer value={record.unmapped} maxHeight="none" />
        </Descriptions.Item>
      </Section>
    </div>
  )
}
