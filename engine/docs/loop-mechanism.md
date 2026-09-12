# 收敛机制完整定义

这是 audit-loop 的**可编码**机制规范。评估器 `evaluate.py` 严格实现本文。
所有指标必须由工具产出，零模型自评。

---

## 1. 迭代轮数

```
HARD_MAX_ROUNDS = 5      # 硬上界，无条件停
SOFT_CONVERGE   = 3      # 期望收敛点
R1 永不收敛              # 首轮审计未验证，不允许停
```

依据：缺陷清除几何衰减（每轮移除剩余缺陷的 40–60%，审计模型间相关性
>60%，多模型并行 ≈ 1.3–1.6 倍单模型召回）。第 1 轮修掉大部分
CRITICAL/HIGH；第 2 轮验证 + 抓回归 + 残余 HIGH；第 3 轮只剩 MEDIUM/边角；
第 4 轮几乎全是 nitpick/假阳；第 5 轮噪声 > 信号。

**轮数是保险丝，不是判据。** 判据靠"可验证发现通量"（§2）。

---

## 2. 自动停止条件

### C1（必要条件，不可绕过）

```
C1 = 本轮经独立验证的新发现中，severity ≥ HIGH 的条数 == 0
     （未验证的不计；MEDIUM/LOW/NIT 不计）
```

### 衰减信号（C1 之外至少满足一个）

| 号 | 条件 | 测量 |
|---|---|---|
| C2 | 发现通量衰减 | 本轮确认发现 ≤ max(1, 0.25 × R1 确认发现) |
| C3 | reward 停滞 | R_t − R_{t−1} < ε 且持续 K=2 轮 |
| C4 | diff 规模衰减 | churn < floor 且 churn < 0.2 × R1 churn |

### 备路径（报告全是噪声）

| 号 | 条件 | 测量 |
|---|---|---|
| C5 | nitpick 饱和 | NIT 占比 ≥ 80% |
| C6 | 管道无变化 | 测试通过率、静态告警、覆盖率三者零变化 |

### 停机规则

```
CONVERGED = (t≥2) ∧ C1 ∧ (C2 ∨ C3 ∨ C4)
         ∨ (t≥2) ∧ C1 ∧ C5 ∧ C6
STOP_HARD = t ≥ HARD_MAX_ROUNDS ∨ 预算耗尽
```

---

## 3. 奖励信号（每轮一个标量 R）

```
R_t = 30·T_t
    + 25·F_t
    − 25·G_t
    − 10·max(0, ΔS_t)
    − 15·A_t
    + 10·clip(ΔC_t, −0.05, +0.05)·100
    −  5·O_t
```

| 符号 | 指标 | 权重 | 测量 |
|---|---|---|---|
| T | 测试通过率 | +30 | passed/(passed+failed) |
| F | 确认修复数（流量） | +25/个 | 上轮确认发现中复现测试红→绿 |
| G | 新引入回归数（流量） | −25/个 | 上轮绿本轮红的测试数 |
| ΔS | 静态告警变化 | −10 | linter WARNING+ 计数差值 |
| A | 架构违背数 | −15/个 | 依赖方向/禁止 API 机器检查命中 |
| ΔC | 覆盖率变化 | +10 | 行覆盖率差值（负向双倍计罚） |
| O | 确认发现存量 | −5/个 | 仍未修复的 ≥MEDIUM 确认发现 |

ε 标定：`ε = max(0.03·Δ₁, 5)`，Δ₁ 为 R1 的 reward 增量。

**修 1 坏 1 净零**——F 与 G 等值（+25/−25），"惩罚 > 奖励"的意图由 §5 的
零容忍回滚落实，不在 R 里二次叠罚。

---

## 4. 审计发现真伪定价（防刷分）

### 验证管线（每个 finding 必过其一，否则不计分）

1. **可复现测试**：落地/验证 agent 写复现测试，改前运行失败（证明存在），
   改后运行通过（证明修复）。两次缺一不可。
2. **静态工具确认**：与 linter/type-checker/SAST 的具体告警映射（同文件行规则）。
3. **最小 PoC 执行**：实际输入触发异常/泄漏/越权，沙箱执行断言可观察结果。

验证必须**独立**：提出发现的模型不能当自己的验证者。

### 审计方信誉分（误报惩罚）

```
w_a ← w_a · (1 + 0.05·TP − 0.15·FP − 0.08·UNVERIFIABLE − 0.10·NIT_FLOOD)
```

- `TP` = 确认真发现数；`FP` = 验证证伪数；`UNVERIFIABLE` = 无法构造验证的
  数量；`NIT_FLOOD` = nit 占比 >50% 的轮次置 1。
- 低信誉审计的 finding 排验证队列末尾。
- `w_a < 0.6` → 该模型熔断（后续轮次移除或换实例）。

### 防落地方作弊

修复确认 = 复现测试红→绿 + 全量套件无新红。落地 agent 不得修改自己修复项
对应的复现测试（测试与修复 diff 分属不同提交，验证器比对测试文件 hash）。

---

## 5. 退化检测与回滚

### 检查点

每轮落地后、评估前打 git 检查点 `checkpoint_t`。所有指标在检查点测量。
保留全部检查点至 loop 结束。

### 退化判定

```
D1（软）: R_t < R_{t−1} − delta_R          # delta_R = 10
D2（硬）: 任一测试由绿转红                 # 零容忍，立即回滚
D3（硬）: 新增架构违背                     # 零容忍
D4（硬）: 新增静态 ERROR                   # 零容忍
```

### 回滚策略

```
硬退化（D2/D3/D4）:
    git revert 本轮落地 diff
    该轮 fix_attempted 标记 fix_failed，重新排队
    regression_strikes += 1
    strikes ≥ 2 → 强制停，交付 best + 遗留清单

软退化（D1）:
    标记 warning，不立即回滚
    t+1 轮仍未恢复到 R_{t−1} → 回锚 argmax R

回滚目标：永远 argmax_i R_i（历史最优），不是上一轮。
```

---

## 6. 资源预算兜底

```
BUDGET = {
  rounds: 5,
  tokens: 按代码库规模预设（例：4 × R1 估计量）,
  wall_time: 预设（例：4h）,
  verify_budget: 每轮最多验证 N=20 个 findings（按信誉排序取前 N）,
}
```

耗尽且未收敛：

1. 冻结（不再产生新 finding）。
2. 回锚 `best_checkpoint = argmax R`。
3. 交付三件套：best commit hash、`residual_risks.json`（verified_true 未修复，
   按严重度）、`unverified_backlog.json`（没来得及验证的）。
4. 终态标注 `CONVERGED: false, REASON: BUDGET_EXHAUSTED`——**绝不把预算耗尽
   伪装成收敛**。

---

## 7. 评估器 Schema

### 输入（每轮）

```yaml
RoundInput:
  round: int
  prev_metrics: Metrics | null      # 首轮为 null
  curr_metrics: Metrics
  findings: list[Finding]           # 本轮审计报告（已去重）
  r1_baseline: {confirmed_findings: int, churn: int}

Metrics:
  test_pass_rate: float
  new_red_tests: int
  static_warnings: int
  static_errors: int
  arch_violations: int
  coverage: float
  open_confirmed: int

Finding:
  id: string
  severity: enum[CRITICAL, HIGH, MEDIUM, LOW, NIT]
  status: enum[reported, verified_true, verified_false, unverifiable,
               fix_confirmed, fix_failed, regression]
```

### 输出

```yaml
Verdict:
  reward: float
  converged: bool
  rollback: bool
  action: enum[CONTINUE, ROLLBACK, STOP]
  reason: enum[CONVERGED, REPEATED_REGRESSION, BUDGET_EXHAUSTED]
  best_checkpoint: string | null
  residual_risks: list | null       # STOP 时
```

---

## 8. 三个关键设计决策（为什么这样设计）

1. **真伪裁决权交给机器证据，不交给任何模型（包括收束模型）。** 收束只
   去重排期。只要"是否收敛"依赖某模型主观判断，该模型就是刷分单点。
2. **轮数是保险丝不是判据。** 判据意义上第 3 轮，保险丝意义上第 5 轮。
   任何"固定跑 N 轮"或"模型说改完了"都落入退化模式。
3. **回滚锚定 argmax R 而非上一轮。** 最坏结果被钳制在"历史最优 + 遗留
   风险清单"，代码不会变差。
