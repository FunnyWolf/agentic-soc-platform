import {useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {useAuthStore} from './stores/auth'
import {RealtimeContext, type RealtimeEvent, type RealtimeStatus} from './realtimeContext'

function websocketUrl(token: string) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/ws/events/?token=${encodeURIComponent(token)}`
}

function closeSocket(socket: WebSocket) {
  if (socket.readyState === WebSocket.CONNECTING) {
    socket.onopen = () => socket.close()
    socket.onmessage = null
    socket.onerror = null
    socket.onclose = null
    return
  }

  if (socket.readyState === WebSocket.OPEN) {
    socket.close()
  }
}

export function RealtimeProvider({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((state) => state.token)
  const [status, setStatus] = useState<RealtimeStatus>('disconnected')
  const [reconnectToken, setReconnectToken] = useState(0)
  const socketRef = useRef<WebSocket | null>(null)
  const handlersRef = useRef(new Set<(event: RealtimeEvent) => void>())
  const commentSubscriptionsRef = useRef(new Map<string, { contentType: string; objectId: string; count: number }>())
  const reconnectTimerRef = useRef<number | null>(null)
  const reconnectAttemptRef = useRef(0)
  const shouldReconnectRef = useRef(false)

  const sendJson = useCallback((payload: unknown) => {
    const socket = socketRef.current
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(payload))
    }
  }, [])

  const sendCommentSubscription = useCallback((type: 'comments.subscribe' | 'comments.unsubscribe', contentType: string, objectId: string) => {
    sendJson({ type, content_type: contentType, object_id: objectId })
  }, [sendJson])

  useEffect(() => {
    if (!token) {
      shouldReconnectRef.current = false
      const socket = socketRef.current
      socketRef.current = null
      if (socket) closeSocket(socket)
      return
    }

    shouldReconnectRef.current = true

    const clearReconnectTimer = () => {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
    }

    const connect = () => {
      clearReconnectTimer()
      setStatus('connecting')
      const socket = new WebSocket(websocketUrl(token))
      socketRef.current = socket

      socket.onopen = () => {
        if (socketRef.current !== socket) {
          socket.close()
          return
        }
        reconnectAttemptRef.current = 0
        setStatus('connected')
        setReconnectToken((current) => current + 1)
        commentSubscriptionsRef.current.forEach(({ contentType, objectId }) => {
          sendCommentSubscription('comments.subscribe', contentType, objectId)
        })
      }

      socket.onmessage = (event) => {
        if (socketRef.current !== socket) return
        let data: unknown
        try {
          data = JSON.parse(event.data)
        } catch {
          return
        }
        if (!data || typeof data !== 'object' || !('type' in data)) return
        const realtimeEvent = data as RealtimeEvent
        if (realtimeEvent.type.startsWith('realtime.') || realtimeEvent.type.startsWith('comments.subscribed')) return
        handlersRef.current.forEach((handler) => handler(realtimeEvent))
      }

      socket.onclose = () => {
        if (socketRef.current !== socket) return
        socketRef.current = null
        setStatus('disconnected')
        if (!shouldReconnectRef.current) return
        const attempt = reconnectAttemptRef.current + 1
        reconnectAttemptRef.current = attempt
        const delay = Math.min(30000, 1000 * 2 ** Math.min(attempt, 5))
        reconnectTimerRef.current = window.setTimeout(connect, delay)
      }

      socket.onerror = () => {
        if (socketRef.current !== socket) return
        if (socket.readyState === WebSocket.OPEN) socket.close()
      }
    }

    reconnectTimerRef.current = window.setTimeout(connect, 0)

    return () => {
      shouldReconnectRef.current = false
      clearReconnectTimer()
      const socket = socketRef.current
      socketRef.current = null
      if (socket) closeSocket(socket)
    }
  }, [sendCommentSubscription, token])

  const subscribe = useCallback((handler: (event: RealtimeEvent) => void) => {
    handlersRef.current.add(handler)
    return () => {
      handlersRef.current.delete(handler)
    }
  }, [])

  const subscribeToComments = useCallback((contentType: string, objectId: string) => {
    const key = `${contentType}:${objectId}`
    const existing = commentSubscriptionsRef.current.get(key)
    if (existing) {
      existing.count += 1
    } else {
      commentSubscriptionsRef.current.set(key, { contentType, objectId, count: 1 })
      sendCommentSubscription('comments.subscribe', contentType, objectId)
    }

    return () => {
      const current = commentSubscriptionsRef.current.get(key)
      if (!current) return
      if (current.count > 1) {
        current.count -= 1
        return
      }
      commentSubscriptionsRef.current.delete(key)
      sendCommentSubscription('comments.unsubscribe', contentType, objectId)
    }
  }, [sendCommentSubscription])

  const value = useMemo(() => ({
    status,
    reconnectToken,
    subscribe,
    subscribeToComments,
  }), [reconnectToken, status, subscribe, subscribeToComments])

  return (
    <RealtimeContext.Provider value={value}>
      {children}
    </RealtimeContext.Provider>
  )
}
