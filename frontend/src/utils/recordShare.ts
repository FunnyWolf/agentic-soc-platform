const shareableResourceKeys = new Set([
  'cases',
  'alerts',
  'artifacts',
  'enrichments',
  'playbooks',
  'knowledge',
])

export function buildRecordSharePath(resourceKey: string, rowId: string | number) {
  if (!shareableResourceKeys.has(resourceKey)) return null
  const normalizedRowId = String(rowId).trim()
  if (!normalizedRowId) return null
  return `/${resourceKey}/${encodeURIComponent(normalizedRowId)}`
}

export function buildRecordShareUrl(resourceKey: string, rowId: string | number) {
  const path = buildRecordSharePath(resourceKey, rowId)
  if (!path) return null
  return `${window.location.origin}${path}`
}
