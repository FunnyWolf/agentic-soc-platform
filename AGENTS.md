### 整体规则

- 除非用户明确说明,否则不允许运行superpower相关skill
- 如 superpower:writing-plan skill禁用,则根据spec直接进行代码实现,除非用户明确要求,实现feature过程中不要生成测试代码
- TODO.md文件是用户手动编辑的,commit时不用处理也不用额外说明.

### 后端规则

backend 是Django实现的后端

- 后端使用uv管理依赖,python在 backend/.venv/Script/python.exe
- 如果功能实现或者优化后,涉及数据库的改动,请确认Django ORM的数据库迁移已完成.

### 前端规则

frontend 是vite + ant design实现的前端

- 如果可以尽量使用ant design 的组件特性和功能实现,如果默认组件效果实现不了或需要定制,才考虑定制化实现
- 尽量使用Ant Design 默认的 CSS,除非用户明确说明或要求
- 前端的所有修改都不需要执行npm build验证

### 项目文档

asf-doc 是使用 vitepress 搭建的文档网站,承载项目的文档,使用独立的 github 仓库和 Cloudflare Pages
文档更新需要先更新zh文档,zh文档定型后再更新对应的en文档.
预先占位图片: 图片占位符不要添加任何描述,用户会根据上下文推断,图片文件名使用img.png img_1.png 这种,方便我拷贝.
VitePress 文档修改后不主动 build，除非用户明确要求

### marketplace

asp-marketplace 有独立的 github 仓库,用于存放 ClaudeCode 插件代码.

# AGENTS.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than
after mistakes.
