const DEFAULT_AUTH_REDIRECT_PATH = '/'
const LOGIN_PATH = '/login'

export function getSafeAuthRedirectPath(value: string | null | undefined) {
  const nextPath = value?.trim()
  if (!nextPath || !nextPath.startsWith('/') || nextPath.startsWith('//') || nextPath.includes('\\')) {
    return DEFAULT_AUTH_REDIRECT_PATH
  }

  try {
    const url = new URL(nextPath, window.location.origin)
    if (url.origin !== window.location.origin || url.pathname === LOGIN_PATH) {
      return DEFAULT_AUTH_REDIRECT_PATH
    }
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return DEFAULT_AUTH_REDIRECT_PATH
  }
}

export function buildLoginRedirectPath(nextPath: string) {
  return `${LOGIN_PATH}?next=${encodeURIComponent(getSafeAuthRedirectPath(nextPath))}`
}

export function getCurrentAuthRedirectPath() {
  return `${window.location.pathname}${window.location.search}${window.location.hash}`
}
