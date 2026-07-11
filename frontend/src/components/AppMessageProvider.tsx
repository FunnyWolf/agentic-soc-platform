import {useLayoutEffect} from 'react'
import {App as AntApp} from 'antd'
import {clearAppMessage, setAppMessage} from '../utils/appMessage'

export default function AppMessageProvider() {
  const {message} = AntApp.useApp()

  useLayoutEffect(() => {
    setAppMessage(message)
    return () => clearAppMessage(message)
  }, [message])

  return null
}
