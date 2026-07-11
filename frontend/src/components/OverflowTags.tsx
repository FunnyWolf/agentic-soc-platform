import type {CSSProperties} from 'react'
import {useMemo} from 'react'
import {Tag, Tooltip} from 'antd'
import {comfortableTagProps} from '../utils/tagStyles'
import {emptyValueNode} from '../utils/recordDisplay'

interface OverflowTagsProps {
  items: unknown
  color?: string
  maxVisible?: number
  getColor?: (item: string) => string
}

const TAG_GAP = 4
const tagStyle: CSSProperties = { marginInlineEnd: 0, flexShrink: 0 }
const tooltipContentStyle: CSSProperties = {
  display: 'inline-flex',
  flexWrap: 'wrap',
  gap: TAG_GAP,
  maxWidth: 360,
}
const tooltipStyles = {
  root: {
    maxWidth: 400,
  },
  container: {
    padding: 0,
    background: 'transparent',
    boxShadow: 'none',
  },
}
const containerStyle: CSSProperties = {
  position: 'relative',
  display: 'inline-flex',
  alignItems: 'center',
  gap: TAG_GAP,
  width: '100%',
  maxWidth: '100%',
  minWidth: 0,
  overflow: 'hidden',
  whiteSpace: 'nowrap',
  verticalAlign: 'middle',
}

export default function OverflowTags({ items, color = 'blue', maxVisible = 2, getColor }: OverflowTagsProps) {
  const values = useMemo(() => Array.isArray(items) ? items.map((item) => String(item)) : [], [items])

  if (!values.length) {
    return emptyValueNode()
  }

  const safeVisibleCount = Math.min(Math.max(maxVisible, 0), values.length)
  const visible = values.slice(0, safeVisibleCount)
  const hidden = values.slice(safeVisibleCount)
  const colorFor = (item: string) => getColor?.(item) || color
  const hiddenTitle = (
    <span style={tooltipContentStyle}>
      {hidden.map((item, index) => (
        <Tag {...comfortableTagProps} key={`hidden-${item}-${index}`} color={colorFor(item)} style={tagStyle}>{item}</Tag>
      ))}
    </span>
  )

  return (
    <span style={containerStyle}>
      {visible.map((item, index) => (
        <Tag {...comfortableTagProps} key={`${item}-${index}`} color={colorFor(item)} style={tagStyle}>{item}</Tag>
      ))}
      {hidden.length > 0 && (
        <Tooltip arrow={false} placement="top" title={hiddenTitle} styles={tooltipStyles}>
          <Tag {...comfortableTagProps} color={color} style={tagStyle}>+{hidden.length}</Tag>
        </Tooltip>
      )}
    </span>
  )
}
