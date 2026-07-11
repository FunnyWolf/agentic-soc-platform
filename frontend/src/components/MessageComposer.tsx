import {useMemo, useState} from 'react'
import type {UploadProps} from 'antd'
import {Alert, Button, Mentions, Tooltip, Upload} from 'antd'
import {message} from '../utils/appMessage'
import {PaperClipOutlined, SendOutlined} from '@ant-design/icons'
import {type Attachment, uploadAttachment} from '../api/attachments'
import {fetchMentionUsers, type MentionUser} from '../api/comments'
import {useAuthStore} from '../stores/auth'
import MessageAttachments from './MessageAttachments'

interface MessageComposerSubmit {
  body: string
  mentionedIds: number[]
  attachments: Attachment[]
}

interface MessageComposerProps {
  placeholder?: string
  submitLabel?: string
  compact?: boolean
  disabled?: boolean
  onSubmit: (input: MessageComposerSubmit) => Promise<void>
}

let mentionUsersCache: MentionUser[] | null = null

async function loadMentionUsers() {
  if (!mentionUsersCache) mentionUsersCache = await fetchMentionUsers()
  return mentionUsersCache
}

export default function MessageComposer({
  placeholder = '@member, press Enter to send, Shift+Enter for a new line',
  submitLabel = 'Send',
  disabled = false,
  onSubmit,
}: MessageComposerProps) {
  const currentUser = useAuthStore((state) => state.user)
  const [body, setBody] = useState('')
  const [users, setUsers] = useState<MentionUser[]>(mentionUsersCache || [])
  const [attachments, setAttachments] = useState<Attachment[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [focused, setFocused] = useState(false)
  const [mentionUsersError, setMentionUsersError] = useState('')

  const mentionableUsers = useMemo(() => {
    return users
      .filter((user) => user.id !== currentUser?.id)
  }, [currentUser?.id, users])

  const mentionedIds = useMemo(() => {
    return mentionableUsers
      .filter((user) => body.includes(`@${user.displayName}`))
      .map((user) => user.id)
  }, [body, mentionableUsers])

  const ensureMentionUsers = async () => {
    if (users.length) return
    setMentionUsersError('')
    try {
      setUsers(await loadMentionUsers())
    } catch {
      setMentionUsersError('Mention suggestions are unavailable.')
    }
  }

  const addFile = async (file: File) => {
    setUploading(true)
    try {
      const attachment = await uploadAttachment(file)
      setAttachments((current) => [...current, attachment])
    } catch {
      message.error('Failed to upload attachment')
    } finally {
      setUploading(false)
    }
  }

  const uploadProps: UploadProps = {
    showUploadList: false,
    multiple: true,
    beforeUpload: (file) => {
      addFile(file)
      return Upload.LIST_IGNORE
    },
  }

  const submit = async () => {
    if (!body.trim() && !attachments.length) return
    setSubmitting(true)
    try {
      await onSubmit({ body, mentionedIds, attachments })
      setBody('')
      setAttachments([])
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      style={{ display: 'grid', gap: 8 }}
      onPaste={(event) => {
        const imageFiles = Array.from(event.clipboardData.files).filter((file) => file.type.startsWith('image/'))
        if (!imageFiles.length) return
        event.preventDefault()
        imageFiles.forEach((file, index) => {
          const extension = file.type.split('/')[1] || 'png'
          const pastedFile = new File([file], `pasted-image-${Date.now()}-${index}.${extension}`, { type: file.type })
          addFile(pastedFile)
        })
      }}
    >
      {mentionUsersError && <Alert type="warning" title={mentionUsersError} showIcon />}
      <div
        style={{
          position: 'relative',
          border: `1px solid ${focused ? '#1677ff' : '#303030'}`,
          borderRadius: 8,
          background: '#141414',
          padding: attachments.length ? '8px 8px 38px' : '0 0 38px',
          boxShadow: focused ? '0 0 0 2px rgba(22, 119, 255, 0.2)' : undefined,
          transition: 'border-color 0.2s, box-shadow 0.2s',
        }}
      >
        {attachments.length > 0 && (
          <div style={{ marginBottom: 8 }}>
            <MessageAttachments
              attachments={attachments}
              removable
              compactCards
              onRemove={(id) => setAttachments((current) => current.filter((attachment) => attachment.id !== id))}
            />
          </div>
        )}
        <Mentions
          rows={3}
          autoSize={{ minRows: 3, maxRows: 5 }}
          value={body}
          onChange={setBody}
          onFocus={() => {
            setFocused(true)
            ensureMentionUsers()
          }}
          onBlur={() => setFocused(false)}
          onSearch={ensureMentionUsers}
          placeholder={placeholder}
          disabled={disabled || submitting}
          variant="borderless"
          style={{
            width: '100%',
          }}
          styles={{
            textarea: {
              background: 'transparent',
              maxHeight: 120,
              overflowY: 'auto',
            },
          }}
          options={mentionableUsers.map((user) => ({ key: String(user.id), value: user.displayName, label: user.displayName }))}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault()
              submit()
            }
          }}
        />
        <div style={{ position: 'absolute', right: 8, bottom: 8, display: 'inline-flex', gap: 4 }}>
          <Upload {...uploadProps}>
            <Tooltip title="Attach file">
              <Button
                type="text"
                size="small"
                icon={<PaperClipOutlined />}
                loading={uploading}
                disabled={disabled || submitting}
              />
            </Tooltip>
          </Upload>
          <Tooltip title={submitLabel}>
            <Button
              type="primary"
              size="small"
              icon={<SendOutlined />}
              loading={submitting}
              disabled={disabled || uploading || (!body.trim() && !attachments.length)}
              onClick={submit}
            />
          </Tooltip>
        </div>
      </div>
    </div>
  )
}
