import client from './client'
import type {SavedTableFilter, TableFilterState} from '../types/records'

export interface ColumnSettings {
  visible: string[]
  order: string[]
  fixedLeft?: string[]
}

export interface TablePreference {
  table_key: string
  page_size: number | null
  column_settings: ColumnSettings | null
  created_at?: string
  updated_at?: string
}

export async function fetchTablePreference(tableKey: string): Promise<TablePreference> {
  const { data } = await client.get<TablePreference>(`/user-table-preferences/${encodeURIComponent(tableKey)}/`)
  return data
}

export async function updateTablePreference(
  tableKey: string,
  input: Partial<Pick<TablePreference, 'page_size' | 'column_settings'>>,
): Promise<TablePreference> {
  const { data } = await client.patch<TablePreference>(`/user-table-preferences/${encodeURIComponent(tableKey)}/`, input)
  return data
}

export async function fetchSavedTableFilters(tableKey: string): Promise<SavedTableFilter[]> {
  const { data } = await client.get<SavedTableFilter[] | { results?: SavedTableFilter[] }>('/saved-table-filters/', {
    params: { table_key: tableKey },
  })
  return Array.isArray(data) ? data : data.results || []
}

export async function createSavedTableFilter(input: {
  table_key: string
  name: string
  state: TableFilterState
  visibility: SavedTableFilter['visibility']
}): Promise<SavedTableFilter> {
  const { data } = await client.post<SavedTableFilter>('/saved-table-filters/', input)
  return data
}

export async function updateSavedTableFilter(
  id: number,
  input: Partial<Pick<SavedTableFilter, 'name' | 'state' | 'visibility'>>,
): Promise<SavedTableFilter> {
  const { data } = await client.patch<SavedTableFilter>(`/saved-table-filters/${id}/`, input)
  return data
}

export async function deleteSavedTableFilter(id: number): Promise<void> {
  await client.delete(`/saved-table-filters/${id}/`)
}
