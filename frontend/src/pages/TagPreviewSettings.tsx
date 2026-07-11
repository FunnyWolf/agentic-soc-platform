import {type ReactNode} from 'react'
import {Card, Flex, Typography} from 'antd'
import {
  alertActionTag,
  alertAnalyticTypeTag,
  alertDispositionTag,
  artifactRoleTag,
  caseCategoryTag,
  choiceTag,
  knowledgeSourceTag,
  productCategoryTag,
  severityTag,
  statusTag,
  verdictTag,
} from '../utils/recordDisplay'

type TagPreviewField = {
  title: string
  values: string[]
  render: (value: string) => ReactNode
  note?: string
}

type TagPreviewGroup = {
  title: string
  fields: TagPreviewField[]
}

const severityValues = ['Unknown', 'Informational', 'Low', 'Medium', 'High', 'Critical']
const confidenceValues = ['Unknown', 'Low', 'Medium', 'High']
const impactValues = ['Unknown', 'Low', 'Medium', 'High', 'Critical']
const priorityValues = ['Unknown', 'Low', 'Medium', 'High', 'Critical']
const riskLevelValues = ['Info', 'Low', 'Medium', 'High', 'Critical', 'Other']
const alertStatusValues = ['Unknown', 'New', 'In Progress', 'Suppressed', 'Resolved', 'Archived', 'Deleted', 'Other']
const caseCategoryValues = ['DLP', 'Email', 'OT', 'Proxy', 'UEBA', 'ThreatIntelligence', 'IAM', 'EDR', 'NDR', 'Cloud', 'SIEM', 'WAF', 'Other']
const verdictValues = ['Unknown', 'False Positive', 'True Positive', 'Disregard', 'Suspicious', 'Benign', 'Test', 'Insufficient Data', 'Security Risk', 'Managed Externally', 'Duplicate', 'Other']
const alertDispositionValues = ['Unknown', 'Allowed', 'Blocked', 'Quarantined', 'Isolated', 'Deleted', 'Dropped', 'Custom Action', 'Approved', 'Restored', 'Exonerated', 'Corrected', 'Partially Corrected', 'Uncorrected', 'Delayed', 'Detected', 'No Action', 'Logged', 'Tagged', 'Alert', 'Count', 'Reset', 'Captcha', 'Challenge', 'Access Revoked', 'Rejected', 'Unauthorized', 'Error', 'Other']
const alertActionValues = ['Unknown', 'Allowed', 'Denied', 'Observed', 'Modified', 'Other']
const alertAnalyticTypeValues = ['Unknown', 'Rule', 'Behavioral', 'Statistical', 'Learning (ML/DL)', 'Fingerprinting', 'Tagging', 'Keyword Match', 'Regular Expressions', 'Exact Data Match', 'Partial Data Match', 'Indexed Data Match', 'Other']
const alertAnalyticStateValues = ['Unknown', 'Active', 'Suppressed', 'Experimental', 'Other']
const alertPolicyTypeValues = ['Identity Policy', 'Resource Policy', 'Service Control Policy', 'Access Control Policy', 'Other']
const productCategoryValues = ['DLP', 'Email', 'OT', 'Proxy', 'UEBA', 'ThreatIntelligence', 'IAM', 'EDR', 'NDR', 'Cloud', 'SIEM', 'WAF', 'Other']
const artifactTypeValues = ['Unknown', 'Hostname', 'IP Address', 'MAC Address', 'User Name', 'Email Address', 'URL String', 'File Name', 'Hash', 'Process Name', 'Resource UID', 'Port', 'Subnet', 'Command Line', 'Country', 'Process ID', 'HTTP User-Agent', 'CWE', 'CVE', 'User Credential ID', 'Endpoint', 'User', 'Email', 'Uniform Resource Locator', 'File', 'Process', 'Geo Location', 'Container', 'Registry', 'Fingerprint', 'Group', 'Account', 'Script Content', 'Serial Number', 'Resource', 'Message', 'Advisory', 'File Path', 'Device', 'Registry Path', 'Other']
const artifactNameValues = ['Unknown', 'Other', 'Source', 'Destination', 'Client', 'Server', 'Actor', 'Target', 'Affected', 'Related', 'Observed', 'Request', 'Response', 'Source IP', 'Destination IP', 'Client IP', 'Server IP', 'Remote IP', 'Local IP', 'NAT IP', 'Proxy IP', 'Forwarded IP', 'DNS Server IP', 'DHCP Server IP', 'VPN IP', 'Source Port', 'Destination Port', 'Client Port', 'Server Port', 'Source MAC', 'Destination MAC', 'Device MAC', 'Domain', 'Source Domain', 'Destination Domain', 'Request Domain', 'DNS Query Name', 'DNS Answer', 'DNS Record', 'URL', 'Request URL', 'Referrer URL', 'Redirect URL', 'Landing URL', 'Phishing URL', 'Callback URL', 'Download URL', 'HTTP Method', 'HTTP User-Agent', 'HTTP Host', 'HTTP Path', 'HTTP Query', 'HTTP Status Code', 'HTTP Request Body', 'HTTP Response Body', 'User', 'User Name', 'User ID', 'User SID', 'User UPN', 'User Email', 'Source User', 'Destination User', 'Actor User', 'Target User', 'Affected User', 'Executing User', 'Logon User', 'Login User', 'Principal User', 'Initiating User', 'Requesting User', 'Owner User', 'Account', 'Account ID', 'Account Name', 'Service Account', 'Admin Account', 'Cloud Account', 'AWS Account ID', 'Azure Tenant ID', 'Azure Subscription ID', 'GCP Project ID', 'Credential ID', 'Access Key ID', 'API Key ID', 'Token ID', 'Session ID', 'Host', 'Hostname', 'Host ID', 'Source Host', 'Destination Host', 'Affected Host', 'Target Host', 'Device', 'Device ID', 'Device Name', 'Endpoint', 'Endpoint ID', 'Asset ID', 'Agent ID', 'Sensor ID', 'Operating System', 'Host OS', 'Host IP', 'Host MAC', 'Host Serial Number', 'Process', 'Process Name', 'Process ID', 'Process Path', 'Process Executable', 'Process Command Line', 'Process Hash', 'Parent Process', 'Parent Process Name', 'Parent Process ID', 'Parent Process Path', 'Parent Process Command Line', 'Parent Process Hash', 'Child Process', 'Child Process Name', 'Child Process ID', 'Child Process Command Line', 'Acting Process', 'Target Process', 'Injected Process', 'File', 'File Name', 'File Path', 'File Extension', 'File Directory', 'File Size', 'File Hash', 'File MD5', 'File SHA1', 'File SHA256', 'File SHA512', 'File Imphash', 'File Signature', 'File Publisher', 'File Owner', 'Download File', 'Attachment File', 'Dropped File', 'Target File', 'Email', 'Sender Email', 'Recipient Email', 'CC Email', 'BCC Email', 'Reply-To Email', 'Return-Path Email', 'Mail From', 'Mail To', 'Mail Subject', 'Mail Message ID', 'Mail Attachment', 'Mail URL', 'Mail Domain', 'Sender Domain', 'Recipient Domain', 'Cloud Resource', 'Cloud Resource ID', 'Cloud Resource Name', 'Cloud Resource ARN', 'Cloud Region', 'Cloud Zone', 'Cloud Service', 'Cloud Role', 'Cloud Policy', 'Cloud Policy ARN', 'Cloud Instance ID', 'Cloud Bucket', 'Cloud Storage Object', 'Cloud Function', 'CloudTrail Event ID', 'Cloud Request ID', 'IAM User', 'IAM Role', 'IAM Group', 'IAM Policy', 'IAM Policy ARN', 'IAM Permission', 'IAM Action', 'IAM Resource', 'Assumed Role', 'Access Key', 'Secret Key ID', 'Permission Set', 'Registry Key', 'Registry Value', 'Registry Path', 'Registry Data', 'Windows Service', 'Scheduled Task', 'WMI Object', 'COM Object', 'Named Pipe', 'Mutex', 'Container', 'Container ID', 'Container Name', 'Container Image', 'Container Image ID', 'Pod', 'Pod Name', 'Namespace', 'Kubernetes Cluster', 'Kubernetes Node', 'Kubernetes Service Account', 'CVE', 'CWE', 'CPE', 'CVSS Score', 'Vulnerable Product', 'Malware Name', 'Malware Family', 'Threat Actor', 'Threat Campaign', 'Attack Technique', 'Attack Tactic', 'IOC', 'YARA Rule', 'Sigma Rule']
const artifactRoleValues = ['Unknown', 'Target', 'Actor', 'Affected', 'Related', 'Other']
const enrichmentTypeValues = ['Unknown', 'Other', 'Threat Intelligence', 'Reputation', 'Geo Location', 'WHOIS', 'DNS', 'Passive DNS', 'Certificate', 'Sandbox', 'Malware Analysis', 'Vulnerability', 'Exposure', 'Asset', 'CMDB', 'Identity', 'Authentication', 'Authorization', 'Behavior', 'Detection', 'Correlation', 'History', 'Remediation', 'Observation', 'External Ticket']
const enrichmentProviderSamples = ['Unknown', 'Other', 'Jira', 'ServiceNow', 'Slack', 'ASP', 'Internal', 'AlienVaultOTX', 'VirusTotal', 'AbuseIPDB', 'Splunk', 'Elastic', 'Microsoft Sentinel', 'CrowdStrike', 'Okta', 'AWS', 'Azure', 'Google Cloud', 'Cloudflare', 'Qualys', 'Tenable', 'MANUAL']
const playbookTagValues = ['System', 'LLM', 'Case', 'Knowledge', 'CMDB', 'Threat Intel', 'Enrichment', 'Custom']
const llmTagValues = ['fast', 'powerful', 'tool_calling', 'structured_output']

const fixedColorTag = (color: string) => (value: string) => choiceTag(value, color)
const sourceTag = (value: string) => choiceTag(value, value === 'custom' ? 'blue' : 'gold')
const playbookTag = (value: string) => {
  const colors: Record<string, string> = { System: 'gold', LLM: 'purple', Case: 'green', Knowledge: 'magenta', CMDB: 'geekblue', 'Threat Intel': 'volcano', Enrichment: 'cyan', Custom: 'blue' }
  return choiceTag(value, colors[value] || 'blue')
}
const siemBackendTag = (value: string) => choiceTag(value, ({ ELK: 'orange', Splunk: 'green' } as Record<string, string>)[value] || 'default')
const auditActionTag = (value: string) => choiceTag(value, ({ create: 'green', update: 'blue', delete: 'red', linked: 'cyan', unlinked: 'orange', deleted: 'red' } as Record<string, string>)[value] || 'default')
const inboxKindTag = (value: string) => choiceTag(value, value === 'system' ? 'purple' : 'blue')
const userRoleTag = (value: string) => choiceTag(value[0].toUpperCase() + value.slice(1), ({ admin: 'purple', user: 'blue', viewer: 'default' } as Record<string, string>)[value])
const authTypeTag = (value: string) => choiceTag(value === 'ldap' ? 'LDAP' : 'Local', value === 'ldap' ? 'geekblue' : 'green')
const activeStatusTag = (value: string) => choiceTag(value === 'true' ? 'Active' : 'Disabled', value === 'true' ? 'green' : 'red')
const llmProviderStatusTag = (value: string) => choiceTag(value === 'true' ? 'Enabled' : 'Disabled', value === 'true' ? 'green' : 'default')
const llmTag = (value: string) => choiceTag(value, ({ fast: 'blue', powerful: 'purple', tool_calling: 'geekblue', structured_output: 'green' } as Record<string, string>)[value] || 'default')
const statusLabelTag = (value: string) => choiceTag(value, ({ Success: 'green', Failed: 'red', Pending: 'gold', Running: 'processing' } as Record<string, string>)[value] || 'default')

const tagPreviewGroups: TagPreviewGroup[] = [
  {
    title: 'Cases',
    fields: [
      { title: 'Case Category', values: caseCategoryValues, render: caseCategoryTag },
      { title: 'Case Severity / Severity (AI)', values: severityValues, render: severityTag },
      { title: 'Case Confidence / Confidence (AI)', values: confidenceValues, render: severityTag },
      { title: 'Case Impact / Impact (AI)', values: impactValues, render: severityTag },
      { title: 'Case Priority / Priority (AI)', values: priorityValues, render: severityTag },
      { title: 'Case Verdict / Verdict (AI)', values: verdictValues, render: verdictTag },
      { title: 'Case Tags', values: ['triage', 'vip', 'needs-review'], render: fixedColorTag('blue'), note: 'Free-form tag list; preview uses sample values.' },
    ],
  },
  {
    title: 'Alerts',
    fields: [
      { title: 'Alert Status', values: alertStatusValues, render: statusTag },
      { title: 'Alert Severity', values: severityValues, render: severityTag },
      { title: 'Alert Confidence', values: confidenceValues, render: severityTag },
      { title: 'Alert Impact', values: impactValues, render: severityTag },
      { title: 'Alert Risk Level', values: riskLevelValues, render: severityTag },
      { title: 'Alert Disposition', values: alertDispositionValues, render: alertDispositionTag },
      { title: 'Alert Action', values: alertActionValues, render: alertActionTag },
      { title: 'Alert Product Category', values: productCategoryValues, render: productCategoryTag },
      { title: 'Alert Analytic Type', values: alertAnalyticTypeValues, render: alertAnalyticTypeTag },
      { title: 'Alert Analytic State', values: alertAnalyticStateValues, render: fixedColorTag('green') },
      { title: 'Alert Policy Type', values: alertPolicyTypeValues, render: fixedColorTag('volcano') },
      { title: 'Alert Product Vendor / Name / Feature', values: ['Elastic', 'Microsoft Sentinel', 'Defender XDR'], render: fixedColorTag('blue'), note: 'Free-form product fields; preview uses sample values.' },
      { title: 'Alert Labels', values: ['phishing', 'endpoint', 'critical-path'], render: fixedColorTag('blue'), note: 'Free-form tag list; preview uses sample values.' },
      { title: 'Alert Data Sources', values: ['edr', 'siem', 'proxy'], render: fixedColorTag('cyan'), note: 'Free-form tag list; preview uses sample values.' },
    ],
  },
  {
    title: 'Artifacts and Enrichments',
    fields: [
      { title: 'Artifact Type', values: artifactTypeValues, render: fixedColorTag('geekblue') },
      { title: 'Artifact Name', values: artifactNameValues, render: fixedColorTag('cyan') },
      { title: 'Artifact Role', values: artifactRoleValues, render: artifactRoleTag },
      { title: 'Enrichment Type', values: enrichmentTypeValues, render: fixedColorTag('magenta') },
      { title: 'Enrichment Provider', values: enrichmentProviderSamples, render: fixedColorTag('purple'), note: 'Provider enum is long; this preview includes the commonly visible provider values used as purple tags.' },
    ],
  },
  {
    title: 'Knowledge, Playbooks, Users, and Settings',
    fields: [
      { title: 'Knowledge Source', values: ['Manual', 'Case'], render: knowledgeSourceTag },
      { title: 'Knowledge Tags', values: ['runbook', 'case-note', 'retention'], render: fixedColorTag('blue'), note: 'Free-form tag list; preview uses sample values.' },
      { title: 'Playbook Job Status', values: ['Success', 'Failed', 'Pending', 'Running'], render: statusLabelTag },
      { title: 'Playbook Definition Source', values: ['official', 'custom'], render: sourceTag },
      { title: 'Playbook Definition Tags', values: playbookTagValues, render: playbookTag },
      { title: 'User Role', values: ['admin', 'user', 'viewer'], render: userRoleTag },
      { title: 'User Auth Type', values: ['local', 'ldap'], render: authTypeTag },
      { title: 'User Status', values: ['true', 'false'], render: activeStatusTag },
      { title: 'LLM Provider Enabled', values: ['true', 'false'], render: llmProviderStatusTag },
      { title: 'LLM Provider Tags', values: llmTagValues, render: llmTag },
    ],
  },
  {
    title: 'Custom Console and System UI',
    fields: [
      { title: 'SIEM YAML Backend', values: ['ELK', 'Splunk'], render: siemBackendTag },
      { title: 'SIEM YAML Key Field', values: ['Key field'], render: fixedColorTag('blue') },
      { title: 'Audit Action', values: ['create', 'update', 'delete', 'linked', 'unlinked', 'deleted'], render: auditActionTag },
      { title: 'Inbox Kind', values: ['system', 'user'], render: inboxKindTag },
      { title: 'Dashboard Risk Artifact Type', values: ['IP Address', 'Hostname', 'User'], render: fixedColorTag('blue'), note: 'Dashboard values come from data; preview uses sample values.' },
      { title: 'Dashboard Risk Artifact Role', values: artifactRoleValues, render: fixedColorTag('purple'), note: 'Dashboard uses a fixed purple tag for role values.' },
    ],
  },
]

function TagPreviewSection({ field }: { field: TagPreviewField }) {
  return (
    <Card size="small" title={field.title} styles={{ body: { padding: 12 } }}>
      <Flex wrap gap={8}>
        {field.values.map((value) => (
          <span key={`${field.title}-${value}`}>{field.render(value)}</span>
        ))}
      </Flex>
      {field.note ? <Typography.Text type="secondary" style={{ display: 'block', marginTop: 8 }}>{field.note}</Typography.Text> : null}
    </Card>
  )
}

export default function TagPreviewSettings() {
  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Flex vertical gap={16}>
        {tagPreviewGroups.map((group) => (
          <Card key={group.title} title={group.title}>
            <Flex vertical gap={12}>
              {group.fields.map((field) => (
                <TagPreviewSection key={field.title} field={field} />
              ))}
            </Flex>
          </Card>
        ))}
      </Flex>
    </div>
  )
}
