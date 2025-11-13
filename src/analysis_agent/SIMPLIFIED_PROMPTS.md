# 简化Prompts - 彻底重写

## 问题

1. **Todo执行完后直接结束** - Agent完成初始todos后认为任务完成，即使tools_count < 5
2. **Prompt太冗长** - 充满emoji，过度的强制性规定，不清晰
3. **没有达到max_turns就结束** - Agent提前生成final_response

## 解决方案

### 1. 简化System Prompt

**之前**: 500+行，充满emoji (🚨 ✓ 🔹等)，过度详细的步骤说明

**现在**: ~40行，简洁清晰，重点突出

关键改进：
```python
=== CRITICAL ===

Minimum: Analyze 5+ tools (most agents have 10-20)
After save_tool_analysis: check progress with get_incremental_analysis_summary()
If tools_count < 5: add new search todos and continue
Complete todos are NOT the end - continue until enough tools analyzed
Task complete when: tools_count >= 5 AND write_report() called

Your work continues beyond initial todos. Create new todos dynamically as you discover more to analyze.
```

**核心要点**：明确说明完成todos不等于完成任务！

### 2. 简化User Message

**之前**: 130+行，6个步骤，大量emoji和格式化

**现在**: 30行，8个简洁步骤，无emoji

关键改进：
```
Important:
- Minimum goal: 5+ tools analyzed (most agents have 10-20 tools)
- After each save_tool_analysis(), check progress
- If tools_count < 5, add new search todos and continue finding/analyzing more tools
- Completing initial todos does NOT mean you are done - continue until enough tools found
- Task is complete only when tools_count >= 5 AND write_report() is called
```

### 3. 核心改变

#### 修改前的问题：
- Agent看到todos全部complete就认为任务完成
- 没有明确说明需要动态添加新todos
- 过度的强制性规定让Agent感到confused

#### 修改后的改进：
- **明确**: "Completing initial todos does NOT mean you are done"
- **指导**: "Create new todos dynamically as you discover more to analyze"
- **目标**: "Continue until tools_count >= 5 AND write_report() is called"
- **简洁**: 移除所有emoji和冗余的格式化
- **清晰**: 每个步骤一行，直接明了

## 文件变化

### `/home/shiqiu/AgentXploit/src/analysis_agent/analysis_agent.py`

**_build_system_prompt()** (lines 82-124)
- 从 ~450行 压缩到 ~40行
- 移除所有emoji
- 移除A, B, C, D部分的冗长说明
- 添加关键声明："Complete todos are NOT the end"

**user_message** (lines 233-263)
- 从 ~130行 压缩到 ~30行
- 移除所有emoji和装饰性格式
- 简化步骤说明
- 强调: "Completing initial todos does NOT mean you are done"

## 备份

原始verbose版本已备份到：
`/home/shiqiu/AgentXploit/src/analysis_agent/analysis_agent.py.backup_verbose`

## 预期效果

修改后，Agent应该：

1. **不会因为todos完成而停止** - 明确告知需要继续
2. **动态添加todos** - 当发现新的文件/tools时添加新todos
3. **持续工作直到目标达成** - tools_count >= 5 AND write_report()被调用
4. **更容易理解任务** - 简洁清晰的指示，无混乱的格式

## 测试验证

运行agent后检查：
1. Agent是否在完成初始todos后继续工作
2. Agent是否动态添加新的todos
3. Agent是否分析了至少5个tools
4. Agent是否调用了write_report()
5. 是否没有过早地生成final_response

## 关键原则

**之前的错误思路**：
- 更多的规定 = 更好的执行
- 强制性语言 = Agent会遵守
- Emoji和格式 = 更清晰

**现在的正确思路**：
- 简洁清晰 > 冗长详细
- 说明目标 > 强制步骤
- 纯文本 > 花哨格式
- 明确关键点 > 重复同样的话

最关键的一句话：**"Completing initial todos does NOT mean you are done"**

这一句话解决了核心问题。
