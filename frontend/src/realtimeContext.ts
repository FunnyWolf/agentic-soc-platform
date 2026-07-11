import {createContext, useContext} from 'react'
import type {InboxMessage} from './api/inbox'
import type {RecordComment} from './api/comments'

export type RealtimeStatus = 'disconnected' | 'connecting' | 'connected'

export type RealtimeEvent =
  | { type: 'inbox.message_created'; event_id: string; occurred_at: string; actor_id: number | null; payload: { message: InboxMessage } }
  | { type: 'inbox.message_deleted'; event_id: string; occurred_at: string; actor_id: number | null; payload: { message_id: number } }
  | { type: 'inbox.message_read'; event_id: string; occurred_at: string; actor_id: number | null; payload: { message_id: number; read_at: string } }
  | { type: 'inbox.all_read'; event_id: string; occurred_at: string; actor_id: number | null; payload: { message_ids: number[]; read_at: string } }
  | { type: 'inbox.unread_count_changed'; event_id: string; occurred_at: string; actor_id: number | null; payload: { count: number } }
  | { type: 'comment.created'; event_id: string; occurred_at: string; actor_id: number | null; payload: { content_type: string; object_id: string; comment: RecordComment } }
  | { type: 'comment.deleted'; event_id: string; occurred_at: string; actor_id: number | null; payload: { content_type: string; object_id: string; comment_id: number } }

export interface RealtimeContextValue {
  status: RealtimeStatus
  reconnectToken: number
  subscribe: (handler: (event: RealtimeEvent) => void) => () => void
  subscribeToComments: (contentType: string, objectId: string) => () => void
}

export const RealtimeContext = createContext<RealtimeContextValue | null>(null)

export function useRealtime() {
  const context = useContext(RealtimeContext)
  if (!context) {
    throw new Error('useRealtime must be used within RealtimeProvider')
  }
  return context
}
