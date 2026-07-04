import {Tabs} from 'antd'
import {Bot, DatabaseSearch, Network, Radar, SlidersHorizontal, Tags, UsersRound} from 'lucide-react'
import LDAPSettings from './LDAPSettings'
import LLMProviderSettings from './LLMProviderSettings'
import RuntimeSettings from './RuntimeSettings'
import SIEMSettings from './SIEMSettings'
import TagPreviewSettings from './TagPreviewSettings'
import ThreatIntelligenceSettings from './ThreatIntelligenceSettings'
import UserManagement from './UserManagement'
import IconTabLabel from '../components/IconTabLabel'

export default function SystemSettings() {
  return (
    <div style={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <Tabs
        defaultActiveKey="users"
        items={[
          {
            key: 'users',
            label: <IconTabLabel icon={UsersRound}>User Management</IconTabLabel>,
            children: <UserManagement />,
          },
          {
            key: 'llm-providers',
            label: <IconTabLabel icon={Bot}>LLM Providers</IconTabLabel>,
            children: <LLMProviderSettings />,
          },
          {
            key: 'threat-intelligence',
            label: <IconTabLabel icon={Radar}>Threat Intelligence</IconTabLabel>,
            children: <ThreatIntelligenceSettings />,
          },
          {
            key: 'siem',
            label: <IconTabLabel icon={DatabaseSearch}>SIEM</IconTabLabel>,
            children: <SIEMSettings />,
          },
          {
            key: 'ldap',
            label: <IconTabLabel icon={Network}>LDAP</IconTabLabel>,
            children: <LDAPSettings />,
          },
          {
            key: 'runtime',
            label: <IconTabLabel icon={SlidersHorizontal}>Runtime</IconTabLabel>,
            children: <RuntimeSettings />,
          },
          {
            key: 'tag-preview',
            label: <IconTabLabel icon={Tags}>Tags</IconTabLabel>,
            children: <TagPreviewSettings />,
          },
        ]}
        style={{ flex: 1, minHeight: 0 }}
        className="system-settings-tabs"
      />
    </div>
  )
}
