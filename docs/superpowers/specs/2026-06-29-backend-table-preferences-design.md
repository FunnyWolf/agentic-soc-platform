# 用户表格偏好后端存储设计

## 背景

当前前端 `DataTable` 将用户表格偏好保存在浏览器 `localStorage`：

- `asp:<tableKey>:savedFilters`：高级筛选弹窗中保存的筛选方案。
- `asp:<tableKey>:columnSettings`：列显示状态和列顺序。
- `asp:<tableKey>:pageSize`：每页行数。

这些配置只存在单个浏览器中，换设备、换浏览器或清理缓存后都会丢失。本次目标是将这些用户偏好改为后端持久化，并让 Saved filters 支持私有和共享两种可见性。

## 决策

采用专用后端资源保存表格偏好：

- 表格级用户偏好单独建模，按 `user + table_key` 保存 `page_size` 和 `column_settings`。
- Saved filters 单独建模，支持 `private` 和 `shared` 可见性。
- 共享 Saved filters 对所有登录用户可见，但只有创建者或管理员可以修改和删除。
- 不迁移旧的 `localStorage` 数据。上线后后端无配置时使用默认表格配置。

## 目标

- 用户的列显示、列顺序、pageSize 存在后端，并按用户和表格隔离。
- Saved filters 存在后端，私有筛选只对创建者可见。
- 共享 Saved filters 对所有登录用户可见。
- 共享 Saved filters 只有创建者或管理员可更新和删除。
- 前端不再读取或写入旧的表格偏好 `localStorage` key。
- 后端接口失败时不影响表格主数据查询。

## 非目标

- 不迁移浏览器中已有的 `localStorage` 表格配置。
- 不恢复当前未保存的搜索、快速筛选、排序、当前页码。
- 不做团队、角色、项目级筛选共享范围。
- 不新增筛选模板市场、收藏、复制等扩展能力。
- 不把列设置做成共享配置。

## 后端设计

### 模块位置

新增 `apps.preferences` 模块承载表格偏好资源。该模块只依赖当前登录用户和 DRF 权限，不嵌入 `User` 的 profile JSON，避免让账号模型继续承担 UI 偏好存储职责。

### `UserTablePreference`

字段：

- `user`：外键到当前用户。
- `table_key`：前端传入的表格标识。
- `page_size`：每页行数，允许空；为空时前端使用默认值 20。
- `column_settings`：JSON，结构为 `{ "visible": string[], "order": string[] }`。
- `created_at`、`updated_at`。

约束：

- `user + table_key` 唯一。
- `table_key` 必填并限制最大长度。
- `column_settings.visible` 和 `column_settings.order` 必须是字符串数组。
- `page_size` 只允许现有前端支持的值：20、50、100。

### `SavedTableFilter`

字段：

- `owner`：创建用户。
- `table_key`：适用的表格标识。
- `name`：筛选名称。
- `state`：JSON，沿用前端 `SavedTableFilter.state`，当前只保存 `{ "quick": {}, "advanced": [...] }`。
- `visibility`：`private` 或 `shared`。
- `created_at`、`updated_at`。

约束：

- `table_key`、`name` 必填并限制最大长度。
- `visibility` 只能是 `private` 或 `shared`。
- `state.quick` 必须是对象，`state.advanced` 必须是数组。
- 同一 owner、同一 table_key 下不强制唯一名称，避免误伤现有前端“Save as”行为。

### 权限

- 所有接口都要求登录。
- `UserTablePreference` 只能读取和修改当前用户自己的记录。
- 私有 Saved filters 只有 owner 可见、可改、可删。
- 共享 Saved filters 所有登录用户可见。
- 共享 Saved filters 只有 owner 或 admin 可改、可删。
- 创建共享 Saved filter 不限制普通用户。

## API 设计

### 表格偏好

`GET /api/user-table-preferences/<table_key>/`

返回当前用户在该表格的偏好。没有记录时返回默认空配置：

```json
{
  "table_key": "cases",
  "page_size": null,
  "column_settings": null
}
```

`PATCH /api/user-table-preferences/<table_key>/`

局部更新当前用户在该表格的偏好。请求可以只包含其中一个字段：

```json
{
  "page_size": 50,
  "column_settings": {
    "visible": ["id", "title", "status"],
    "order": ["id", "title", "status", "severity"]
  }
}
```

### Saved filters

`GET /api/saved-table-filters/?table_key=<table_key>`

返回当前用户可见的筛选方案：自己的私有筛选和全部共享筛选。

`POST /api/saved-table-filters/`

创建私有或共享筛选：

```json
{
  "table_key": "cases",
  "name": "High severity open cases",
  "visibility": "shared",
  "state": {
    "quick": {},
    "advanced": []
  }
}
```

`PATCH /api/saved-table-filters/<id>/`

更新名称、状态或可见性。权限按 owner/admin 校验。

`DELETE /api/saved-table-filters/<id>/`

删除筛选。权限按 owner/admin 校验。

## 前端设计

### `DataTable`

`DataTable` 挂载时根据 `resolvedTableKey` 加载后端偏好：

- 后端返回 `page_size` 时作为初始 pageSize，否则使用 20。
- 后端返回有效 `column_settings` 时按现有 `readColumnSettings` 的归一化逻辑处理：过滤不存在的列、补齐新列、保留 locked columns。
- 后端没有偏好或加载失败时使用默认列配置和默认 pageSize。

用户修改列显示、列顺序、pageSize 时，前端调用偏好接口保存。保存失败时保留当前界面状态，但提示用户保存失败，避免误以为配置已经跨设备同步。

### `TableFilterModal`

弹窗打开时通过 `GET /api/saved-table-filters/?table_key=...` 加载 Saved filters，不再读取 `localStorage`。

操作映射：

- `Save as`：`POST /api/saved-table-filters/`。
- `Update`：`PATCH /api/saved-table-filters/<id>/`。
- `Delete`：`DELETE /api/saved-table-filters/<id>/`。
- `Load`：只更新当前弹窗草稿，不立即修改后端。
- `Search`：应用当前草稿到表格状态，不自动保存。

Saved filters 列表需要显示私有/共享状态。共享筛选如果当前用户不是 owner 且不是 admin，更新和删除按钮应禁用或隐藏。

### 旧 `localStorage`

实现后不再读取和写入以下 key：

- `asp:<tableKey>:savedFilters`
- `asp:<tableKey>:columnSettings`
- `asp:<tableKey>:columns`
- `asp:<tableKey>:pageSize`

旧 key 不需要主动清理。

## 错误处理

- 表格偏好加载失败：表格继续使用默认配置，提示一次加载失败。
- 表格偏好保存失败：保留当前 UI 状态，提示保存失败。
- Saved filters 加载失败：弹窗显示空列表，并提示加载失败。
- Saved filters 创建、更新、删除失败：不更新本地列表，提示对应操作失败。
- 后端校验失败返回 400，权限失败返回 403，不存在返回 404。

## 数据迁移

新增数据库迁移：

- 创建 `user_table_preferences` 表。
- 创建 `saved_table_filters` 表。
- 添加必要索引：
  - `user_table_preferences(user_id, table_key)` 唯一索引。
  - `saved_table_filters(table_key, visibility)` 查询索引。
  - `saved_table_filters(owner_id, table_key)` 查询索引。

不需要从浏览器 `localStorage` 回填数据。

## 验证标准

后端：

- 迁移文件生成并可应用。
- 用户只能读取和修改自己的表格偏好。
- 私有 Saved filter 只对 owner 可见。
- 共享 Saved filter 对其他登录用户可见。
- 共享 Saved filter 只有 owner 或 admin 可修改和删除。
- 非法 `page_size`、非法 `column_settings`、非法 `state` 返回 400。

前端：

- 新用户进入表格时使用默认列配置和 pageSize 20。
- 修改列显示、列顺序、pageSize 后刷新页面仍保持配置。
- 同一用户换浏览器后能看到后端保存的配置。
- 不同用户的列设置和 pageSize 互不影响。
- 私有 Saved filter 只在创建用户下可见。
- 共享 Saved filter 在其他用户下可见，但非 owner 非 admin 不能更新或删除。
