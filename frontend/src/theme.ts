import type {ThemeConfig} from 'antd'
import {theme} from 'antd'
import {fontFamilyMono, fontFamilySans} from './utils/typography'

const themeConfig: ThemeConfig = {
  algorithm: theme.darkAlgorithm,
  token: {
    colorPrimary: '#1677ff',
    fontFamily: fontFamilySans,
    fontFamilyCode: fontFamilyMono,
    fontSize: 14,
    lineHeight: 1.5715,
  },
}

export const severityColors: Record<string, string> = {
  Critical: '#ff4d4f',
  High: '#fa541c',
  Medium: '#faad14',
  Low: '#13c2c2',
  Info: '#1677ff',
  Informational: '#1677ff',
}

export const severityTagColors: Record<string, string> = {
  Critical: 'red',
  High: 'volcano',
  Medium: 'gold',
  Low: 'cyan',
  Info: 'blue',
  Informational: 'blue',
}

export default themeConfig
