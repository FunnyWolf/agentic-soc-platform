import {useCallback, useEffect, useMemo, useState} from 'react'
import {Alert, Button, Input, List, Popconfirm, Space, Tooltip} from 'antd'
import {message} from '../utils/appMessage'
import {MessageOutlined, ReloadOutlined, SearchOutlined} from '@ant-design/icons'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import {createComment, deleteComment, fetchComments, type RecordComment} from '../api/comments'
import useCursorFeed from '../hooks/useCursorFeed'
import FeedLoadMore from './FeedLoadMore'
import MessageAttachments from './MessageAttachments'
import MessageComposer from './MessageComposer'
import UserAvatar from './UserAvatar'
import {tabularNumbersStyle, typography} from '../utils/typography'
import {useRealtime} from '../realtimeContext'

dayjs.extend(relativeTime)

interface DiscussionThreadProps {
  contentType: string
  objectId: string
}

function commentMatches(comment: RecordComment, keyword: string): boolean {
  return comment.body.toLowerCase().includes(keyword) ||
    comment.author_username.toLowerCase().includes(keyword) ||
    comment.parent_body.toLowerCase().includes(keyword) ||
    comment.parent_author_username.toLowerCase().includes(keyword)
}

function timeLabel(value: string) {
  const timestamp = dayjs(value)
  if (!timestamp.isValid()) return value
  return timestamp.fromNow()
}

function authorLabel(comment: RecordComment) {
  return comment.author_name || comment.author_username || 'Unknown user'
}

function parentLabel(comment: RecordComment) {
  return comment.parent_author_name || comment.parent_author_username || 'Unknown user'
}

function ReplyContext({ comment }: { comment: RecordComment }) {
  if (!comment.parent) return null
  return (
    <>
      <span style={{ color: 'rgba(255,255,255,0.45)' }}> replied to </span>
      <span>{parentLabel(comment)}</span>
      <Tooltip title={comment.parent_body || 'No text content'}>
        <MessageOutlined style={{ color: 'rgba(255,255,255,0.45)', fontSize: typography.compact.fontSize, marginInlineStart: 4 }} />
      </Tooltip>
    </>
  )
}

function DeleteCommentAction({ onDelete }: { onDelete: () => Promise<void> }) {
  return (
    <Popconfirm
      title="Delete comment?"
      description="This comment and its replies will be deleted."
      okText="Delete"
      cancelText="Cancel"
      okButtonProps={{ danger: true }}
      onConfirm={onDelete}
    >
      <Button type="link" danger size="small" style={{ padding: 0 }}>Delete</Button>
    </Popconfirm>
  )
}

function CommentItem({
  comment,
  hovered,
  onReply,
  onDelete,
  onHover,
}: {
  comment: RecordComment
  hovered: boolean
  onReply: (comment: RecordComment) => void
  onDelete: (comment: RecordComment) => Promise<void>
  onHover: (comment: RecordComment | null) => void
}) {
  return (
    <List.Item
      style={{ borderBlockEnd: '1px solid #222', alignItems: 'flex-start', display: 'block' }}
      onMouseEnter={() => onHover(comment)}
      onMouseLeave={() => onHover(null)}
    >
      <List.Item.Meta
        avatar={<UserAvatar username={comment.author_username || comment.author_name} avatarUrl={comment.author_avatar_url} />}
        title={(
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
            <Space size={8} wrap>
              <span>{authorLabel(comment)}</span>
              <ReplyContext comment={comment} />
            </Space>
            <Tooltip title={new Date(comment.created_at).toLocaleString()}>
              <span style={{ ...typography.compact, ...tabularNumbersStyle, color: 'rgba(255,255,255,0.35)', whiteSpace: 'nowrap' }}>
                {timeLabel(comment.created_at)}
              </span>
            </Tooltip>
          </div>
        )}
        description={(
          <div style={{ display: 'grid', gap: 8 }}>
            {comment.body && <div style={{ ...typography.body, whiteSpace: 'pre-wrap', color: 'rgba(255,255,255,0.75)' }}>{comment.body}</div>}
            <MessageAttachments attachments={comment.attachments || []} />
          </div>
        )}
      />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, visibility: hovered ? 'visible' : 'hidden' }}>
        <Button size="small" type="link" style={{ padding: 0 }} onClick={() => onReply(comment)}>Reply</Button>
        {comment.can_delete && <DeleteCommentAction onDelete={() => onDelete(comment)} />}
      </div>
    </List.Item>
  )
}

export default function DiscussionThread({ contentType, objectId }: DiscussionThreadProps) {
  const [search, setSearch] = useState('')
  const [replyTo, setReplyTo] = useState<RecordComment | null>(null)
  const [hoveredCommentId, setHoveredCommentId] = useState<number | null>(null)
  const [actionLoading, setActionLoading] = useState(false)
  const {reconnectToken, subscribe, subscribeToComments} = useRealtime()

  const fetchCommentPage = useCallback((cursor?: string | null) => {
    return fetchComments(contentType, objectId, { cursor, pageSize: 20 })
  }, [contentType, objectId])

  const {
    items: comments,
    setItems: setComments,
    loadingInitial,
    loadingMore,
    hasMore,
    error: loadError,
    refresh: refreshComments,
    loadMore,
  } = useCursorFeed({
    fetchPage: fetchCommentPage,
    getItemKey: (comment) => comment.id,
    errorMessage: 'Failed to load comments',
  })

  useEffect(() => {
    return subscribeToComments(contentType, objectId)
  }, [contentType, objectId, subscribeToComments])

  useEffect(() => {
    return subscribe((event) => {
      if (event.type === 'comment.created') {
        if (event.payload.content_type !== contentType || event.payload.object_id !== objectId) return
        const nextComment = event.payload.comment
        setComments((current) => {
          if (current.some((comment) => comment.id === nextComment.id)) {
            return current.map((comment) => comment.id === nextComment.id ? nextComment : comment)
          }
          return [...current, nextComment]
        })
        return
      }
      if (event.type === 'comment.deleted') {
        if (event.payload.content_type !== contentType || event.payload.object_id !== objectId) return
        setComments((current) => current.filter((comment) => comment.id !== event.payload.comment_id))
        setReplyTo((current) => current?.id === event.payload.comment_id ? null : current)
      }
    })
  }, [contentType, objectId, setComments, subscribe])

  useEffect(() => {
    if (reconnectToken === 0) return
    refreshComments()
  }, [reconnectToken, refreshComments])

  const filteredComments = useMemo(() => {
    if (!search.trim()) return comments
    const keyword = search.toLowerCase()
    return comments.filter((comment) => commentMatches(comment, keyword))
  }, [comments, search])

  const submit = async (input: { body: string; mentionedIds: number[]; attachments: { id: number }[] }) => {
    setActionLoading(true)
    try {
      const createdComment = await createComment({
        content_type: contentType,
        object_id: objectId,
        body: input.body,
        parent: replyTo?.id,
        mentions: input.mentionedIds,
        attachment_ids: input.attachments.map((attachment) => attachment.id),
      })
      setReplyTo(null)
      setComments((current) => current.some((comment) => comment.id === createdComment.id) ? current : [...current, createdComment])
      message.success('Comment added')
    } catch {
      message.error('Failed to add comment')
    } finally {
      setActionLoading(false)
    }
  }

  const removeComment = async (comment: RecordComment) => {
    setActionLoading(true)
    try {
      await deleteComment(comment.id)
      setReplyTo(null)
      setComments((current) => current.filter((item) => item.id !== comment.id))
      message.success('Comment deleted')
    } catch {
      message.error('Failed to delete comment')
    } finally {
      setActionLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: '0 4px 24px' }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <Input
          prefix={<SearchOutlined />}
          placeholder="Search comments"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          allowClear
        />
        <Button icon={<ReloadOutlined />} loading={loadingInitial} onClick={refreshComments} style={{ width: 32, flex: '0 0 32px' }} />
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        {loadError && <Alert type="error" title={loadError} showIcon style={{ marginBottom: 12 }} />}
        <List
          loading={loadingInitial}
          dataSource={filteredComments}
          loadMore={hasMore ? <FeedLoadMore label="Load more comments" loading={loadingMore} onClick={loadMore} /> : null}
          locale={{ emptyText: 'No comments yet' }}
          renderItem={(comment) => (
            <CommentItem
              comment={comment}
              hovered={hoveredCommentId === comment.id}
              onReply={setReplyTo}
              onDelete={removeComment}
              onHover={(nextComment) => setHoveredCommentId(nextComment?.id ?? null)}
            />
          )}
        />
      </div>
      {replyTo && (
        <div style={{ color: 'rgba(255,255,255,0.45)', margin: '8px 0' }}>
          Replying to {replyTo.author_name || replyTo.author_username}
          <Button type="link" size="small" onClick={() => setReplyTo(null)}>Cancel</Button>
        </div>
      )}
      <MessageComposer
        placeholder="@member, press Enter to publish, Shift+Enter for a new line"
        disabled={actionLoading}
        submitLabel="Comment"
        onSubmit={submit}
      />
    </div>
  )
}
