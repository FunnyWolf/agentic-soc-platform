import {Fragment} from 'react'
import {choiceTag} from '../utils/recordDisplay'

interface TagListProps {
  items: unknown
  color?: string
}

export default function TagList({ items, color = 'blue' }: TagListProps) {
  if (!Array.isArray(items)) return choiceTag(String(items || ''), color)

  return (
    <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 4 }}>
      {items.map((item, index) => (
        <Fragment key={`${String(item)}-${index}`}>
          {choiceTag(String(item), color)}
        </Fragment>
      ))}
    </span>
  )
}
