# Team Tasks - SoliGuard Project

## Team Members & Roles

| Name | Role | Focus Area |
|------|------|-------------|
| **Peace Stephen** | Tech Lead | AI/LLM Integration, Backend, Runtime |
| **Joel Emmanuel Adinoyi** | Security Lead | Web3 Security, Blockchain, Vuln Detection |
| **Mayowa Sunusi** | Frontend Lead | UI/UX, React Components, Reports |
| **Yusuf Sanusi** | Frontend Dev | API Integration, Frontend-Backend, Tools |
| **Abubakar Adamu** | Product/QA | Documentation, Validation, Testing, Config |

---

## All Modules in Project

| # | Module | Files | Purpose |
|---|--------|-------|---------|
| 1 | `audit-engine/` | 9 | Smart contract audit engine |
| 2 | `blockchain/` | 8 | Blockchain integration (Etherscan, RPC) |
| 3 | `chains/` | 8 | Multi-step audit chains |
| 4 | `commands/` | 9 | Command handlers & CLI |
| 5 | `config/` | 8 | JSON configuration files |
| 6 | `context-management/` | 9 | Context management |
| 7 | `core/` | 9 | Orchestration & routing |
| 8 | `exploitation/` | 9 | Exploitation (Web3 focused) |
| 9 | `hooks/` | 9 | Pre/post hooks |
| 10 | `hunts/` | 2 | Hunt specifications |
| 11 | `integrations/` | 9 | LLM + tool bridges |
| 12 | `mcp/` | 9 | MCP protocol |
| 13 | `models/` | 9 | Model definitions |
| 14 | `providers/` | 9 | Provider specs |
| 15 | `recon/` | 8 | Recon pipeline |
| 16 | `reports/` | 9 | Report generation |
| 17 | `rules/` | 9 | Detection rules |
| 18 | `runtime/` | 9 | Process layer |
| 19 | `sessions/` | 9 | Session management |
| 20 | `severity/` | 9 | Scoring & triage |
| 21 | `skills/` | 9 | Skill definitions |
| 22 | `solidity-analysis/` | 9 | Solidity analysis |
| 23 | `storage/` | 9 | Storage layer |
| 24 | `system-prompt/` | 9 | System prompts |
| 25 | `task-persistence/` | 9 | Task persistence |
| 26 | `tasks/` | 9 | Task definitions |
| 27 | `tools/` | 9 | Tool definitions |
| 28 | `validations/` | 8 | Validation logic |
| 29 | `vuln-detection/` | 9 | Vulnerability detection |

---

## Task Assignments

### 🔐 Peace Stephen - Tech Lead

**Priority 1 - Core Backend:**
- `backend/main.py`
- `backend/core/gemini_client.py`
- `backend/core/prompt_engine.py`
- `backend/core/pdf_generator.py`
- `backend/routes/audit_code.py`

**Priority 2 - Runtime & Core:**
- `runtime/loader.py`
- `runtime/repl.py`
- `runtime/executor.py`
- `runtime/session.py`
- `runtime/runner.py`
- `runtime/parser.py`
- `runtime/factory.py`
- `runtime/reporter.py`

**Priority 3 - Core Orchestration:**
- `core/router.py`
- `core/orchestrator.py`
- `core/memory.py`
- `core/escalation.py`
- `core/loader.py`
- `core/executor.py`

**Priority 4 - Integrations:**
- `integrations/llm_client.py`
- `integrations/provider_bridge.py`
- `integrations/stream_handler.py`
- `integrations/model_loader.py`
- `integrations/integration_factory.py`

**Priority 5 - System Prompts:**
- `system-prompt/base_prompt.py`
- `system-prompt/hunting_prompt.py`
- `system-prompt/chain_prompt.py`
- `system-prompt/repl_prompt.py`
- `prompts/audit_system.md`
- `prompts/patch_format.md`

**Priority 6 - Models:**
- `models/model_registry.py`
- `models/claude_opus_4.py`
- `models/claude_opus_4_5.py`

---

### 🛡️ Joel Emmanuel Adinoyi - Security Lead

**Priority 1 - Vulnerability Detection:**
- `vuln-detection/reentrancy_detector.py`
- `vuln-detection/overflow_detector.py`
- `vuln-detection/access_control_detector.py`
- `vuln-detection/unchecked_call_detector.py`
- `vuln-detection/front_run_detector.py`
- `vuln-detection/timestamp_detector.py`
- `vuln-detection/selfdestruct_detector.py`
- `vuln-detection/dos_detector.py`

**Priority 2 - Blockchain Integration:**
- `blockchain/provider.py`
- `blockchain/etherscan_client.py`
- `blockchain/sourcify_client.py`
- `blockchain/rpc_client.py`
- `blockchain/contract_fetcher.py`
- `blockchain/abi_parser.py`
- `blockchain/transaction_analyzer.py`
- `blockchain/block_explorer.py`
- `backend/utils/chain_fetcher.py`
- `backend/core/vuln_taxonomy.py`

**Priority 3 - Solidity Analysis:**
- `solidity-analysis/parser.py`
- `solidity-analysis/ast_analyzer.py`
- `solidity-analysis/taint_analysis.py`
- `solidity-analysis/control_flow.py`
- `solidity-analysis/data_flow.py`
- `solidity-analysis/call_graph.py`
- `solidity-analysis/gas_analysis.py`
- `solidity-analysis/decompiler.py`

**Priority 4 - Audit Engine:**
- `audit-engine/scanner.py`
- `audit-engine/crawler.py`
- `audit-engine/injector.py`
- `audit-engine/fuzzer.py`
- `audit-engine/reporter.py`
- `audit-engine/plugin_manager.py`
- `audit-engine/config_loader.py`
- `audit-engine/scheduler.py`

**Priority 5 - Chains:**
- `chains/full_audit.py`
- `chains/code_audit.py`
- `chains/reentrancy_scan.py`
- `chains/overflow_scan.py`
- `chains/access_control_scan.py`
- `chains/gas_optimization.py`
- `chains/layer2_audit.py`
- `chains/bounty_chain.py`

**Priority 6 - Exploitation:**
- `exploitation/exploit_engine.py`
- `exploitation/payload_generator.py`
- `exploitation/exploit_runner.py`
- `exploitation/exploit_validator.py`
- `exploitation/exploit_reporter.py`
- `exploitation/exploit_parser.py`
- `exploitation/exploit_loader.py`
- `exploitation/exploit_store.py`

**Priority 7 - Sample Contracts:**
- `sample_contracts/clean_contract.sol`
- `sample_contracts/reentrancy_vuln.sol`
- `sample_contracts/overflow_vuln.sol`

---

### 🎨 Mayowa Sunusi - Frontend Lead

**Priority 1 - Core UI Components:**
- `frontend/src/App.jsx`
- `frontend/src/components/CodeEditor.jsx`
- `frontend/src/components/FileUpload.jsx`
- `frontend/src/components/ChainInput.jsx`
- `frontend/src/components/AuditReport.jsx`

**Priority 2 - Reports:**
- `reports/reporter.py`
- `reports/report_generator.py`
- `reports/report_formatter.py`
- `reports/html_reporter.py`
- `reports/markdown_reporter.py`
- `reports/pdf_reporter.py`
- `reports/report_template.py`
- `reports/report_factory.py`

**Priority 3 - Severity & Scoring:**
- `severity/critical.py`
- `severity/high.py`
- `severity/medium.py`
- `severity/low.py`
- `severity/triage.py`
- `severity/validate.py`
- `severity/report_template.py`
- `severity/complete_report.py`

**Priority 4 - Frontend Config:**
- `frontend/package.json`

---

### 🔗 Yusuf Sanusi - Frontend Dev

**Priority 1 - API Integration:**
- `frontend/src/api.js`
- `backend/routes/audit_file.py`
- `backend/routes/audit_chain.py`

**Priority 2 - Tools:**
- `tools/http_probe.py`
- `tools/code_scanner.py`
- `tools/pattern_matcher.py`
- `tools/payload_generator.py`
- `tools/diff_analyzer.py`
- `tools/cvss_scorer.py`
- `tools/regex_scanner.py`
- `tools/tool_loader.py`

**Priority 3 - Providers:**
- `providers/anthropic.py`
- `providers/qwen.py`
- `providers/ollama.py`
- `providers/groq.py`
- `providers/provider_factory.py`
- `providers/provider_config.py`
- `providers/provider_loader.py`
- `providers/provider_registry.py`

**Priority 4 - Sessions:**
- `sessions/session_manager.py`
- `sessions/context_manager.py`
- `sessions/hunt_session.py`
- `sessions/secure_session.py`
- `sessions/session_store.py`
- `sessions/session_loader.py`
- `sessions/session_parser.py`
- `sessions/session_factory.py`

**Priority 5 - Tasks:**
- `tasks/task_definitions.py`
- `tasks/task_templates.py`
- `tasks/task_loader.py`
- `tasks/task_executor.py`
- `tasks/task_scheduler.py`
- `tasks/task_queue.py`
- `tasks/task_result.py`
- `tasks/task_history.py`

---

### 📋 Abubakar Adamu - Product & QA

**Priority 1 - Configuration:**
- `config/settings.json`
- `config/models.json`
- `config/session.json`
- `config/providers.json`
- `config/hunts.json`
- `config/chains.json`
- `config/tools.json`
- `config/severity.json`

**Priority 2 - Validation:**
- `validations/validations.py`
- `validations/sanitizers.py`
- `validations/input_validator.py`
- `validations/output_validator.py`
- `validations/schema_validator.py`
- `validations/payload_validator.py`
- `validations/regex_validator.py`
- `validations/validator_factory.py`

**Priority 3 - Storage:**
- `storage/storage.py`
- `storage/cache.py`
- `storage/file_storage.py`
- `storage/database.py`
- `storage/key_value.py`
- `storage/blob_storage.py`
- `storage/persistence.py`
- `storage/storage_factory.py`

**Priority 4 - Context & Memory:**
- `context-management/context.py`
- `context-management/context_loader.py`
- `context-management/context_saver.py`
- `context-management/context_parser.py`
- `context-management/context_manager.py`
- `context-management/context_factory.py`
- `context-management/context_validator.py`
- `context-management/context_storage.py`
- `memory/memory.py`
- `memory/context.py`
- `memory/session_memory.py`
- `memory/working_memory.py`

**Priority 5 - Task Persistence:**
- `task-persistence/task_persistence.py`
- `task-persistence/persistence_manager.py`
- `task-persistence/task_saver.py`
- `task-persistence/task_loader.py`
- `task-persistence/task_serializer.py`
- `task-persistence/task_backup.py`
- `task-persistence/task_restore.py`
- `task-persistence/persistence_factory.py`

**Priority 6 - Documentation:**
- `docs/ARCHITECTURE.md`
- `prompts/vuln_categories.md`
- `rules/detection_rules.md`
- `rules/payload_rules.md`
- `rules/bypass_rules.md`
- `rules/sqli_rules.md`
- `rules/xss_rules.md`
- `rules/rce_rules.md`
- `rules/ssrf_rules.md`
- `rules/idor_rules.md`
- `rules/auth_rules.md`

**Priority 7 - Other Modules:**
- `commands/commands.py`
- `commands/cli.py`
- `commands/command_parser.py`
- `commands/command_loader.py`
- `commands/command_executor.py`
- `commands/command_registry.py`
- `commands/command_validator.py`
- `commands/command_factory.py`
- `hunts/hunt_specs.py`
- `recon/target_profiling.py`
- `recon/endpoint_discovery.py`
- `recon/param_fuzzing.py`
- `recon/header_analysis.py`
- `recon/js_analysis.py`
- `recon/subdomain_enum.py`
- `recon/tech_detection.py`
- `recon/service_enum.py`
- `hooks/pre_hooks.py`
- `hooks/post_hooks.py`
- `hooks/auth_hooks.py`
- `hooks/validation_hooks.py`
- `hooks/logging_hooks.py`
- `hooks/cleanup_hooks.py`
- `hooks/event_hooks.py`
- `hooks/custom_hooks.py`
- `mcp/protocol.py`
- `mcp/handlers.py`
- `mcp/client.py`
- `mcp/server.py`
- `mcp/tools.py`
- `mcp/resources.py`
- `mcp/prompts.py`
- `mcp/transport.py`
- `skills/skill_registry.py`
- `skills/custom_skills.py`
- `skills/skill_loader.py`
- `skills/skill_executor.py`
- `skills/skill_validator.py`
- `skills/skill_context.py`
- `skills/skill_hooks.py`
- `skills/skill_storage.py`
- `models/qwen3_235b.py`
- `models/qwen3_security.py`
- `models/qwen3_coder.py`
- `models/qwen_vl.py`
- `models/ghost_local.py`

---

## Module Ownership Summary

| Module | Owner | Files |
|--------|-------|-------|
| `backend/` | Peace | 10 |
| `runtime/` | Peace | 9 |
| `core/` | Peace | 8 |
| `integrations/` | Peace | 9 |
| `system-prompt/` | Peace | 8 |
| `models/` | Peace/Abubakar | 8 |
 `hooks/` | Peace | 8 |
 | `rules/` | Peace | 9 |
| `mcp/` | Peace | 8 |
| `vuln-detection/` | Joel | 8 |
| `blockchain/` | Joel | 8 |
| `solidity-analysis/` | Joel | 8 |
| `audit-engine/` | Joel | 8 |
| `chains/` | Joel | 8 |
| `exploitation/` | Joel | 8 |
| `sample_contracts/` | Joel | 3 |
| `frontend/src/components/` | Mayowa | 5 |
| `reports/` | Mayowa | 8 |
| `severity/` | Mayowa | 8 |
| `frontend/` | Mayowa/Yusuf | 2 |
| `tools/` | Yusuf | 8 |
| `sessions/` | Yusuf | 8 |
| `tasks/` | Yusuf | 8 |
| `config/` | Abubakar | 8 |
| `validations/` | Abubakar | 8 |
| `storage/` | Abubakar | 8 |
| `context-management/` | Abubakar | 8 |
| `task-persistence/` | Abubakar | 8 |
| `commands/` | Abubakar | 9 |
| `hunts/` | Abubakar | 1 |
| `recon/` | Abubakar | 8 |
| `skills/` | Abubakar | 8 |
| `memory/` | Abubakar | 4 |
---

## Workflow

1. **Daily Standup** - Share progress on assigned tasks
2. **Code Review** - Push to branch, tag reviewer
3. **Testing** - Abubakar tests each module before merge
4. **Documentation** - Update docs as you go

---

*Team SoliGuard - GDG Abuja × Build with AI Sprint*
*TCP (The Coding Peace) Ecosystem*