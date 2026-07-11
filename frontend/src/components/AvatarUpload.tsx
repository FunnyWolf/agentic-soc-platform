import type {UploadProps} from 'antd'
import {Upload} from 'antd'
import {message} from '../utils/appMessage'
import {CameraOutlined} from '@ant-design/icons'
import ImgCrop from 'antd-img-crop'
import client from '../api/client'
import {uploadAttachment} from '../api/attachments'
import type {AuthUser} from '../stores/auth'
import UserAvatar from './UserAvatar'

interface AvatarUploadProps {
  user: Pick<AuthUser, 'username' | 'avatar_url' | 'has_avatar'>
  endpoint: string
  onChange: (user: AuthUser) => void
  disabled?: boolean
}

export default function AvatarUpload({ user, endpoint, onChange, disabled }: AvatarUploadProps) {
  const uploadAvatar: UploadProps['customRequest'] = async ({ file, onError, onSuccess }) => {
    const uploadFile = file as File
    if (!uploadFile.type.startsWith('image/')) {
      const error = new Error('Please select an image file')
      message.error(error.message)
      onError?.(error)
      return
    }

    try {
      const attachment = await uploadAttachment(uploadFile)
      const { data } = await client.put<AuthUser>(endpoint, { attachment_id: attachment.id })
      onChange(data)
      message.success('Avatar updated')
      onSuccess?.(data)
    } catch (error) {
      message.error('Failed to update avatar')
      onError?.(error as Error)
    }
  }

  return (
    <ImgCrop
      rotationSlider
      showReset
      aspect={1}
      cropShape="round"
      modalTitle="Crop Avatar"
      modalOk="Save"
    >
      <Upload accept="image/*" showUploadList={false} customRequest={uploadAvatar} disabled={disabled}>
        <span className={`avatar-upload-trigger${disabled ? ' avatar-upload-trigger-disabled' : ''}`}>
          <UserAvatar username={user.username} avatarUrl={user.avatar_url} size={64} />
          {!disabled && <span className="avatar-upload-mask"><CameraOutlined /></span>}
        </span>
      </Upload>
    </ImgCrop>
  )
}
