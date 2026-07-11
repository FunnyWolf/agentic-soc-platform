import axios from 'axios'
import {useAuthStore} from '../stores/auth'
import {buildLoginRedirectPath, getCurrentAuthRedirectPath} from '../utils/authRedirect'

const client = axios.create({ baseURL: '/api' })

client.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

client.interceptors.response.use(
  (resp) => resp,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout()
      window.location.href = buildLoginRedirectPath(getCurrentAuthRedirectPath())
    }
    return Promise.reject(error)
  },
)

export default client
