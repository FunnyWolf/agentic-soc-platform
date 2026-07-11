import {type ReactNode, useCallback, useEffect, useMemo, useState} from 'react'
import {message} from '../utils/appMessage'
import DataTable from './DataTable'
import {fetchResourceMetadata} from '../api/metadata'
import type {AdvancedFilterFieldConfig, MetadataResponse, OpenResourceOptions, ResourceColumn, ResourceFilterConfig} from '../types/records'

type RecordRow = Record<string, unknown>

interface RelatedRecordsTableProps {
  endpoint: string
  tableKey: string
  resourceKey: string
  columns: ResourceColumn<RecordRow>[]
  filters: ResourceFilterConfig[]
  advancedFilters?: AdvancedFilterFieldConfig[]
  baseParams?: Record<string, string | number | boolean | undefined>
  onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
  actions?: ReactNode
  refreshToken?: unknown
}

export default function RelatedRecordsTable({ endpoint, tableKey, resourceKey, columns, filters, advancedFilters, baseParams, onOpenResource, actions, refreshToken }: RelatedRecordsTableProps) {
  const [metadata, setMetadata] = useState<MetadataResponse | null>(null)
  const [localRefreshToken, setLocalRefreshToken] = useState(0)

  useEffect(() => {
    fetchResourceMetadata().then(setMetadata).catch(() => setMetadata(null))
  }, [])

  const requestRefresh = useCallback(() => {
    setLocalRefreshToken((current) => current + 1)
  }, [])

  const openResourceFromTable = useCallback((targetResourceKey: string, targetRowId: string | number, options?: OpenResourceOptions) => {
    onOpenResource?.(targetResourceKey, targetRowId, {
      ...options,
      onChanged: () => {
        options?.onChanged?.()
        requestRefresh()
      },
    })
  }, [onOpenResource, requestRefresh])

  const resolvedRefreshToken = useMemo(
    () => `${String(refreshToken ?? '')}:${localRefreshToken}`,
    [localRefreshToken, refreshToken],
  )

  return (
    <div style={{ height: '100%', padding: 16, boxSizing: 'border-box' }}>
      <DataTable
        endpoint={endpoint}
        tableKey={tableKey}
        savedFiltersKey={resourceKey}
        columns={columns}
        filters={filters}
        advancedFilters={advancedFilters}
        metadata={metadata?.resources?.[resourceKey]}
        onOpenResource={onOpenResource ? openResourceFromTable : undefined}
        onRowClick={onOpenResource
          ? (record) => {
            const rowId = record.id
            if (typeof rowId !== 'string' && typeof rowId !== 'number') {
              message.error('Cannot open related record without an ID')
              return
            }
            openResourceFromTable(resourceKey, rowId)
          }
          : undefined}
        baseParams={baseParams}
        actions={actions}
        refreshToken={resolvedRefreshToken}
        dense
        fillParent
      />
    </div>
  )
}
