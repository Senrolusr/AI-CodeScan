# 测试与真实运行问题记录（2026-06-25）

本文件记录本轮测试/真实审计运行中发现的主要问题，供下次继续修改时参考。

> 背景：当前后端单元测试 `backend/tests` 运行结果为 `449 passed`，但真实审计运行仍暴露出前后端契约、模型连通性测试、审计规划数量、阶段执行顺序等问题。这些问题不一定会被现有 pytest 覆盖。

---

## 1. 前后端部分未对齐

### 现象

前端页面展示的审计事件、阶段进度或运行状态与后端真实执行情况不一致。

### 主要问题

#### 1.1 审计事件接口参数不一致

前端 API 中事件接口定义类似：

```js
export const getAuditEvents = (id, afterId = 0, limit = 100) =>
  api.get(`/audits/${id}/events`, { params: { after_id: afterId, limit } })
```

后端当前期望参数：

```txt
after_id
limit
```

但前端某些事件视图可能按对象参数调用，例如：

```js
getAuditEvents(props.id, params)
```

其中 `params` 可能是：

```js
{
  since_sequence,
  limit,
}
```

这会导致请求实际变成：

```txt
/api/audits/{id}/events?after_id=[object Object]&limit=100
```

从而导致事件增量拉取异常。

#### 1.2 审计事件返回结构不一致

后端当前返回结构类似：

```json
{
  "task_id": 1,
  "after_id": 123,
  "events": []
}
```

但前端某些组件期望结构可能是：

```json
{
  "items": [],
  "last_sequence": 123
}
```

因此前端读取 `payload.items` 时拿不到后端返回的 `events`，表现为事件丢失、页面不刷新、阶段顺序看起来异常。

### 影响

- 审计事件页面可能无法正常显示事件；
- 阶段状态可能看起来跳跃或乱序；
- 后端实际已执行，但前端未正确呈现；
- 用户容易误判为审计流程本身出错。

### 建议修复

优先统一前端到当前后端契约：

```js
const res = await getAuditEvents(props.id, lastSequence.value, 500)
const incoming = res.data?.events || []
lastSequence.value = Number(res.data?.after_id || lastSequence.value || 0)
```

或者新增专门的 execution-events 后端接口，让后端返回前端期望的结构：

```json
{
  "items": [],
  "last_sequence": 123
}
```

---

## 2. 模型配置测试失败，但实际审计能用

### 现象

在模型配置页面点击“测试连接”可能失败，但用同一模型配置实际跑审计时可以正常工作。

### 主要问题

#### 2.1 测试失败的详细诊断信息被统一异常处理吞掉

模型测试接口在失败时会抛出包含丰富信息的 `HTTPException`，例如：

```python
raise HTTPException(
    400,
    {
        "message": "连通性测试失败",
        "detail": result["message"],
        "preferred_mode": result.get("preferred_mode"),
        "successful_mode": result.get("successful_mode"),
        "strict_success": result.get("strict_success"),
        "strict_successful_mode": result.get("strict_successful_mode"),
        "attempts": result.get("attempts", []),
        "model": result.get("model"),
    },
)
```

但后端统一异常处理会将其包装成类似：

```json
{
  "code": "HTTP_400",
  "message": "连通性测试失败",
  "details": {}
}
```

导致以下诊断信息丢失：

```txt
attempts
preferred_mode
successful_mode
strict_success
strict_successful_mode
model
```

前端又可能只读取：

```js
e.response?.data?.detail
```

统一错误结构中没有 `detail` 后，前端只能显示泛化错误，用户无法看到具体失败原因。

#### 2.2 测试探测参数过于保守

模型测试连接可能使用较小的请求参数，例如：

```python
temperature = 0
max_tokens = 16
```

真实审计调用通常使用配置中的温度和更大的 token 限制，例如几千 token。

这会导致某些模型或兼容 OpenAI 协议的代理服务在测试场景下返回空内容、截断内容或非预期内容，但真实审计可以正常完成。

#### 2.3 测试连接没有和真实调用保持一致的重试策略

真实审计调用通常有重试逻辑，而模型测试连接更像一次性探测。临时网络抖动或上游偶发错误可能导致测试失败，但实际审计通过重试可以成功。

### 影响

- 用户误以为模型不可用；
- 实际可用模型被错误标记为测试失败；
- 前端无法展示详细失败原因；
- 调试模型配置时缺少必要诊断信息。

### 建议修复

1. 模型测试失败时保留完整诊断数据。
   - 方案 A：HTTP 200 返回 `success: false` 和完整 result；
   - 方案 B：继续返回 400，但将详细信息放入统一错误结构的 `details` 字段。

2. 前端同时兼容：

```js
e.response?.data?.detail
e.response?.data?.details
```

3. 放宽测试探测参数：

```python
max_tokens = 128  # 或 256
temperature = config.temperature or 0.1
```

4. 给测试连接增加至少 1 次重试，使其更接近真实审计调用行为。

---

## 3. 第二阶段规划出需要 7 个审计，但实际只跑了 4 个

### 现象

第二阶段规划结果显示需要多个审计 agent，例如 7 个，但实际运行中只看到 4 个审计被执行。

### 主要问题

后端 supervisor 中存在 agent 数量上限，例如：

```python
FALLBACK_MAX_AGENT_COUNT = 7
```

同时系统有基线阶段会被固定保留，例如：

```txt
2, 7, 9
```

也就是 3 个 baseline agent 会占用预算。

因此当最大 agent 数为 7 时，非 baseline 阶段最多只有：

```txt
7 - 3 = 4
```

所以如果第二阶段识别出 5 个非 baseline 审计阶段，例如：

```txt
3, 4, 5, 6, 8
```

最终最多只能保留 4 个，剩余 1 个会被裁掉。

### 可能导致“7 个变 4 个”的原因

#### 情况 A：7 是总 agent 数，其中 3 个是 baseline

总计划：

```txt
baseline: 2, 7, 9
non-baseline: 4 个
```

用户在页面上更关注业务审计阶段时，就会感觉“只跑了 4 个”。

#### 情况 B：裁剪阶段未明确展示

被裁掉的阶段可能进入 `skipped_agents` 或仅在内部结构中存在，但前端没有清楚展示：

```txt
哪些阶段被跳过
为什么跳过
是否因为 agent 数量上限
```

#### 情况 C：裁剪排序不一定按风险证据强度

如果裁剪逻辑按 stage 编号或列表插入顺序保留前 4 个，而不是按证据强度排序，则可能出现：

- 高风险阶段被裁掉；
- stage 8 等排序靠后的阶段被跳过；
- 规划结果和实际执行不符合用户预期。

### 影响

- 规划结果与实际执行数量不一致；
- 用户无法判断被跳过阶段是否合理；
- 高风险审计阶段可能被错误裁掉；
- 前端显示“需要审计”，但后端没有执行完整。

### 建议修复

1. 如果目标是完整审计，将上限从 7 提高到 8 或 9：

```python
FALLBACK_MAX_AGENT_COUNT = 9
```

因为阶段 1 是架构阶段，阶段 2-9 最多 8 个子审计 agent。

2. 裁剪时按证据强度排序，而不是按 stage 编号或插入顺序。

3. 被裁掉的阶段必须写入日志、审计事件和前端提示，例如：

```txt
阶段 8 被跳过：超过最大 agent 数 7
```

4. 区分展示：

```txt
规划 agent 数
实际执行 agent 数
跳过 agent 数
跳过原因
```

---

## 4. 审计阶段三还没完成就先跑复核，然后才回去跑第三阶段

### 现象

真实运行中看起来像：

```txt
阶段 3 还没完成 -> 先跑了复核 -> 又回去跑阶段 3
```

### 主要问题

这里可能同时有真实执行顺序问题和前端展示问题。

#### 4.1 `current_stage` 是单个字段，但多个并发 agent 都会写

多个审计子 agent 是并发执行的。每个 agent 可能都会更新：

```python
task.current_stage = stage_num
```

并发写入会导致 `current_stage` 取决于最后提交的 agent，而不是实际流程顺序。

可能出现：

```txt
stage 5 先写 current_stage=5
stage 7 后写 current_stage=7
stage 3 最后写 current_stage=3
```

前端看到的就是阶段跳跃、倒退或乱序。

#### 4.2 复核阶段没有独立 phase 状态

当前审计流程并不是严格线性的：

```txt
阶段 1：架构分析
阶段 2：规划
阶段 3-N：多个 agent 并发审计
复核：检查是否需要重跑
必要时 rerun 部分阶段
最终汇总
```

如果只用一个数字字段 `current_stage` 表示当前进度，会天然无法表达：

```txt
planning
auditing
reviewing
rerunning
completed
```

#### 4.3 复核触发 rerun 后，阶段列表可能没有重新加载

复核阶段如果决定重跑某些阶段，后端会重置对应阶段状态，然后再次执行 agent。

如果 reset 后没有重新加载最新 stages，就可能出现：

- 内存中的 stage 状态是旧的；
- 数据库中的 stage 状态是新的；
- 前端轮询看到的状态与真实执行状态不一致；
- 看起来像“先复核，再回去跑之前的阶段”。

### 影响

- 前端进度条/阶段时间线显示混乱；
- 用户误以为审计流程乱序；
- review/rerun 行为无法被正确解释；
- 并发 agent 会竞争写同一个 `current_stage` 字段。

### 建议修复

#### 后端

1. 不要让并发子 agent 直接写 `AuditTask.current_stage`。

子 agent 只更新自己的：

```txt
AuditStage.status
AuditStage.started_at
AuditStage.completed_at
AuditStage.error_message
```

整体进度由主流程统一计算。

2. `current_stage` 改成派生值或单调值。

例如：

```txt
最高已完成阶段
当前 running 阶段集合
```

如果继续保留单字段，不应允许并发写竞争。

3. 增加独立流程字段，例如：

```txt
phase = planning
phase = auditing
phase = reviewing
phase = rerunning
phase = completed
```

前端应优先展示 `phase`，而不是只看 `current_stage`。

4. 复核触发 rerun 后，重置阶段状态之后必须重新加载 stages：

```python
stages = await _reload_task_stages(session, task.id)
```

再调用执行逻辑。

5. 在复核、重跑、跳过阶段时写入明确事件：

```txt
review_started
review_completed
rerun_requested
stage_reset_for_rerun
stage_rerun_started
stage_rerun_completed
```

#### 前端

1. 不要只依赖 `current_stage` 判断审计顺序。

2. 以 `AuditStage[]` 为主展示状态：

```txt
pending
running
completed
failed
skipped
```

3. 同时展示当前 phase：

```txt
规划中 / 审计中 / 复核中 / 重跑中 / 已完成
```

4. 先修复事件接口契约，否则前端可能继续误判顺序。

---

## 建议修复优先级

### P0：先修前后端事件接口对齐

原因：事件流不准会直接影响所有运行状态判断。

需要处理：

- `after_id` vs `since_sequence`；
- `events` vs `items`；
- `after_id` vs `last_sequence`；
- 前端调用 `getAuditEvents` 的参数格式。

### P1：修复阶段状态模型

原因：`current_stage` 被并发 agent 竞争写入，不能可靠表达真实进度。

需要处理：

- 子 agent 不再直接写 `task.current_stage`；
- 增加或派生 `phase`；
- 前端以 `AuditStage[]` 和事件为准展示。

### P2：修复 agent 规划数量与裁剪展示

原因：规划 7 个但只执行 4 个会让用户认为漏审。

需要处理：

- 提高或移除 `FALLBACK_MAX_AGENT_COUNT = 7`；
- 按风险证据强度裁剪；
- 明确展示跳过阶段和原因。

### P3：修复模型配置测试逻辑

原因：测试失败但实际可用会误导用户，但不一定阻断审计。

需要处理：

- 保留测试失败详情；
- 放宽测试 probe 参数；
- 增加重试；
- 前端兼容统一错误结构。

---

## 下次修改时建议检查的重点文件

```txt
backend/routers/audits.py
backend/routers/llm_configs.py
backend/main.py
backend/services/supervisor.py
backend/services/audit_worker.py
backend/services/llm_client.py
backend/services/execution_events.py
frontend/src/api/index.js
frontend/src/views/AuditDetail.vue
frontend/src/views/ExecutionEvents.vue
frontend/src/views/LlmConfigs.vue
frontend/src/composables/useAuditDerived.js
frontend/src/stores/auditDetail.js
```

---

## 当前结论

现有 pytest 全部通过，但这不能说明真实审计流程完全正确。当前主要问题集中在：

1. 前后端事件和状态契约不一致；
2. 模型测试接口与真实审计调用行为不一致；
3. 审计 agent 数量被上限和 baseline 占位裁剪；
4. 并发审计阶段竞争写 `current_stage`，导致进度显示和实际流程不一致。

下次修复建议先从事件接口和阶段状态模型入手，否则其他问题即使修了，前端仍可能显示混乱。
