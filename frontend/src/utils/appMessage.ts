import {App as AntApp} from 'antd'

type MessageApi = ReturnType<typeof AntApp.useApp>['message']

let activeMessage: MessageApi | null = null

export function setAppMessage(message: MessageApi) {
  activeMessage = message
}

export function clearAppMessage(message: MessageApi) {
  if (activeMessage === message) activeMessage = null
}

function getMessage() {
  if (!activeMessage) {
    throw new Error('Ant Design message API is not ready')
  }
  return activeMessage
}

export const message = new Proxy({} as MessageApi, {
  get(_target, property: keyof MessageApi) {
    const api = getMessage()
    const value = api[property]
    return typeof value === 'function' ? value.bind(api) : value
  },
})
