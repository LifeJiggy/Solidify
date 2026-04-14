# Team Tasks - SoliGuard Project

## Team Members & Roles

| Name | Role | Focus Area |
|------|------|-------------|
| **Peace Stephen** | Tech Lead | AI/LLM Integration, Backend, Runtime, Core, Providers |
| **Joel Emmanuel Adinoyi** | Security Lead | Web3 Security, Blockchain, Vuln Detection |
| **Mayowa Sunusi** | Frontend Lead | UI/UX, React Components, Reports |
| **Yusuf Sanusi** | Frontend Dev | API Integration, Tools, Sessions, Tasks |
| **Abubakar Adamu** | Product/QA | Documentation, Validation, Config, Testing |

---

## 40-Feature Roadmap

### 🔴 Critical Features (MVP)

| # | Feature | Module |
|---|---------|--------|
| 01 | Core Solidity Audit Engine | `audit-engine/`, `backend/` |
| 02 | Severity Classification + CVSS Scoring | `severity/`, `backend/core/cvss_scorer.py` |
| 03 | Side-by-Side Patch Generation | `reports/`, `frontend/components/AuditReport.jsx` |
| 04 | File Upload Audit (.sol) | `frontend/components/FileUpload.jsx`, `audit-engine/multi_contract.py` |
| 05 | On-Chain Contract Scan (Etherscan) | `blockchain/`, `backend/utils/chain_fetcher.py` |
| 06 | PDF Audit Report Export | `reports/pdf_reporter.py`, `backend/core/pdf_generator.py` |

### 🟠 High Priority Features

| # | Feature | Module |
|---|---------|--------|
| 07 | Multi-Vulnerability Chaining Detection | `chains/multi_vuln_chain.py` |
| 08 | Proof-of-Concept Exploit Generation | `exploitation/`, `tools/payload_generator.py` |
| 09 | Reentrancy Attack Simulation | `vuln-detection/reentrancy_detector.py`, `exploitation/reentrancy_poc.py` |
| 10 | Integer Overflow/Underflow PoC | `vuln-detection/overflow_detector.py` |
| 11 | Access Control Bypass PoC | `vuln-detection/access_control_detector.py` |
| 12 | Flash Loan Attack Surface Detection | `vuln-detection/flash_loan_detector.py` |
| 13 | Multi-Chain Support (BSC, Polygon, Arbitrum, Base) | `blockchain/multi_chain.py`, `frontend/components/chain_selector.py` |
| 14 | DeFi Protocol Pattern Recognition | `defi-patterns/` |
| 15 | NFT Contract Audit Mode | `defi-patterns/nft_pattern.py` |
| 16 | Audit History + Session Memory | `sessions/audit_session.py`, `storage/audit_history.py` |
| 17 | Natural Language Audit Query | `system-prompt/natural_language_prompt.py`, `frontend/components/NaturalLanguageQuery.jsx` |
| 18 | Vulnerability Confidence Scoring | `severity/confidence_scoring.py`, `frontend/components/ConfidenceScore.jsx` |

### 🟡 Medium Priority Features

| # | Feature | Module |
|---|---------|--------|
| 19 | Gas Optimization Analysis | `solidity-analysis/gas_analysis.py`, `chains/gas_optimization.py` |
| 20 | Front-Running Attack Detection + PoC | `vuln-detection/front_run_detector.py` |
| 21 | Sandwich Attack Surface Scanner | `vuln-detection/sandwich_detector.py` |
| 22 | Oracle Manipulation Detection | `vuln-detection/oracle_manipulation_detector.py` |
| 23 | Price Manipulation PoC Generator | `exploitation/payload_generator.py` |
| 24 | Upgradeable Proxy Pattern Audit | `solidity-analysis/proxy_pattern.py` |
| 25 | Governance Attack Surface Detection | `defi-patterns/governance_pattern.py` |
| 26 | Token Economics Vulnerability Scan | `defi-patterns/token_economics.py` |
| 27 | Cross-Contract Interaction Analysis | `solidity-analysis/cross_contract.py` |
| 28 | Sourcify + IPFS Source Verification | `blockchain/sourcify_client.py`, `blockchain/ipfs_client.py` |
| 29 | Foundry/Hardhat Test Case Generator | `tools/test_generator.py` |
| 30 | Markdown Audit Report Export | `reports/markdown_reporter.py` |
| 31 | Contract Diff Auditor (v1 vs v2) | `tools/diff_analyzer.py`, `reports/diff_report.py` |
| 32 | Real-Time Audit Streaming (SSE) | `runtime/stream_handler.py`, `backend/routes/audit_stream.py` |
| 33 | Multi-File / Multi-Contract Project Audit | `audit-engine/multi_contract.py`, `audit-engine/project_zip.py` |
| 34 | ERC-20 / ERC-721 / ERC-1155 Compliance Check | `defi-patterns/erc_compliance.py` |
| 35 | On-Chain Transaction History Risk Scan | `blockchain/transaction_analyzer.py` |
| 36 | Wallet Drainer Pattern Detection | `vuln-detection/wallet_drainer_detector.py` |

### 🟢 Roadmap Features

| # | Feature | Module |
|---|---------|--------|
| 37 | Audit REST API (External Integrations) | `mcp/rest_api.py` |
| 38 | VS Code Extension | `vscode-extension/` |
| 39 | CI/CD Pipeline Integration | `ci-cd/` |
| 40 | SoliGuard Agent Mode (autonomous) | `tasks/agent_task.py`, `core/orchestrator.py` |

---

## Task Assignments

### 🔐 Peace Stephen - Tech Lead (AI/LLM Integration)

**ALL LLM/AI Integration - Provider Layer:**
- `providers/gemini.py` - Default provider
- `providers/anthropic.py` - BYOA
- `providers/qwen.py` - BYOA
- `providers/ollama.py` - BYOA
- `providers/groq.py` - BYOA
- `providers/nvidia.py` - BYOA (NIM)
- `providers/openai.py` - BYOA
- `providers/google.py` - BYOA (Vertex)
- `providers/provider_factory.py`
- `providers/provider_config.py`
- `providers/provider_loader.py`
- `providers/provider_registry.py`

- `integrations/llm_client.py` - Main LLM client
- `integrations/provider_bridge.py`
- `integrations/stream_handler.py`
- `integrations/model_loader.py`
- `integrations/integration_factory.py`
- `integrations/anthropic_bridge.py`
- `integrations/openai_bridge.py`
- `integrations/nvidia_bridge.py`
- `integrations/qwen_bridge.py`
- `integrations/ollama_bridge.py`
- `integrations/file_injector.py`
- `integrations/tool_caller.py`

- `models/model_registry.py`
- `models/claude_opus_4.py`
- `models/claude_opus_4_5.py`
- `models/qwen3_235b.py`
- `models/qwen3_security.py`
- `models/qwen3_coder.py`
- `models/qwen_vl.py`
- `models/ghost_local.py`

**System Prompts (Gemini Default):**
- `system-prompt/base_prompt.py`
- `system-prompt/hunting_prompt.py`
- `system-prompt/chain_prompt.py`
- `system-prompt/repl_prompt.py`
- `system-prompt/natural_language_prompt.py` - Feature #17
- `system-prompt/context_prompt.py`
- `system-prompt/exploit_prompt.py`
- `system-prompt/report_prompt.py`
- `prompts/audit_system.md`
- `prompts/patch_format.md`
- `prompts/exploit_poc_template.md` - Feature #8
- `prompts/vuln_categories.md`

**Critical Features (MVP):**
- `backend/main.py` - Entry point
- `backend/core/gemini_client.py` - Core audit engine
- `backend/core/prompt_engine.py` - Prompt templates
- `backend/core/pdf_generator.py` - PDF export
- `backend/core/cvss_scorer.py` - CVSS scoring
- `backend/routes/audit_code.py`
- `backend/routes/audit_stream.py` - Feature #32 SSE

**Runtime & Core:**
- `runtime/loader.py`
- `runtime/repl.py`
- `runtime/executor.py`
- `runtime/session.py`
- `runtime/runner.py`
- `runtime/parser.py`
- `runtime/factory.py`
- `runtime/reporter.py`
- `runtime/stream_handler.py` - Feature #32

**Core Orchestration:**
- `core/router.py`
- `core/orchestrator.py` - Feature #40 Agent mode
- `core/memory.py`
- `core/escalation.py`
- `core/loader.py`
- `core/executor.py`
- `core/reporter.py`

---

### 🛡️ Joel Emmanuel Adinoyi - Security Lead

**Vulnerability Detection:**
- `vuln-detection/reentrancy_detector.py` - Feature #9
- `vuln-detection/overflow_detector.py` - Feature #10
- `vuln-detection/access_control_detector.py` - Feature #11
- `vuln-detection/unchecked_call_detector.py`
- `vuln-detection/front_run_detector.py` - Feature #20
- `vuln-detection/timestamp_detector.py`
- `vuln-detection/selfdestruct_detector.py`
- `vuln-detection/dos_detector.py`
- `vuln-detection/flash_loan_detector.py` - Feature #12
- `vuln-detection/sandwich_detector.py` - Feature #21
- `vuln-detection/oracle_manipulation_detector.py` - Feature #22
- `vuln-detection/wallet_drainer_detector.py` - Feature #36

**Blockchain Integration (Critical #5):**
- `blockchain/provider.py`
- `blockchain/etherscan_client.py`
- `blockchain/sourcify_client.py`
- `blockchain/rpc_client.py`
- `blockchain/contract_fetcher.py`
- `blockchain/abi_parser.py`
- `blockchain/transaction_analyzer.py` - Feature #35
- `blockchain/block_explorer.py`
- `blockchain/multi_chain.py` - Feature #13
- `blockchain/ipfs_client.py` - Feature #28
- `backend/utils/chain_fetcher.py`
- `backend/core/vuln_taxonomy.py`

**Solidity Analysis:**
- `solidity-analysis/parser.py`
- `solidity-analysis/ast_analyzer.py`
- `solidity-analysis/taint_analysis.py`
- `solidity-analysis/control_flow.py`
- `solidity-analysis/data_flow.py`
- `solidity-analysis/call_graph.py`
- `solidity-analysis/gas_analysis.py` - Feature #19
- `solidity-analysis/decompiler.py`
- `solidity-analysis/cross_contract.py` - Feature #27
- `solidity-analysis/proxy_pattern.py` - Feature #24

**Audit Engine:**
- `audit-engine/scanner.py`
- `audit-engine/crawler.py`
- `audit-engine/injector.py`
- `audit-engine/fuzzer.py`
- `audit-engine/reporter.py`
- `audit-engine/plugin_manager.py`
- `audit-engine/config_loader.py`
- `audit-engine/scheduler.py`
- `audit-engine/multi_contract.py` - Feature #33
- `audit-engine/project_zip.py` - Feature #33

**Chains:**
- `chains/full_audit.py`
- `chains/code_audit.py`
- `chains/reentrancy_scan.py`
- `chains/overflow_scan.py`
- `chains/access_control_scan.py`
- `chains/gas_optimization.py`
- `chains/layer2_audit.py`
- `chains/bounty_chain.py`
- `chains/multi_vuln_chain.py` - Feature #7
- `chains/defi_audit.py` - Feature #14

**Exploitation:**
- `exploitation/exploit_engine.py`
- `exploitation/payload_generator.py` - Feature #23
- `exploitation/exploit_runner.py`
- `exploitation/exploit_validator.py`
- `exploitation/exploit_reporter.py`
- `exploitation/exploit_parser.py`
- `exploitation/exploit_loader.py`
- `exploitation/exploit_store.py`
- `exploitation/reentrancy_poc.py` - Feature #9

**DeFi Patterns:**
- `defi-patterns/amm_pattern.py`
- `defi-patterns/lending_pattern.py`
- `defi-patterns/yield_farming.py`
- `defi-patterns/stablecoin.py`
- `defi-patterns/governance_pattern.py` - Feature #25
- `defi-patterns/token_economics.py` - Feature #26
- `defi-patterns/erc_compliance.py` - Feature #34
- `defi-patterns/nft_pattern.py` - Feature #15

**Sample Contracts:**
- `sample_contracts/clean_contract.sol`
- `sample_contracts/reentrancy_vuln.sol`
- `sample_contracts/overflow_vuln.sol`
- `sample_contracts/access_control_vuln.sol`
- `sample_contracts/flash_loan_vuln.sol`
- `sample_contracts/nft_vuln.sol`
- `sample_contracts/defi_vuln.sol`

---

### 🎨 Mayowa Sunusi - Frontend Lead

**Core UI Components:**
- `frontend/src/App.jsx`
- `frontend/src/components/CodeEditor.jsx`
- `frontend/src/components/FileUpload.jsx`
- `frontend/src/components/ChainInput.jsx`
- `frontend/src/components/AuditReport.jsx` - Side-by-side diff
- `frontend/src/components/SeverityBadge.jsx` - Feature #2
- `frontend/src/components/ConfidenceScore.jsx` - Feature #18
- `frontend/src/components/NaturalLanguageQuery.jsx` - Feature #17
- `frontend/src/components/multi_upload.py` - Feature #33
- `frontend/src/components/chain_selector.py` - Feature #13
- `frontend/package.json`

**Reports:**
- `reports/reporter.py`
- `reports/report_generator.py`
- `reports/report_formatter.py`
- `reports/html_reporter.py`
- `reports/markdown_reporter.py` - Feature #30
- `reports/pdf_reporter.py` - Feature #6
- `reports/report_template.py`
- `reports/report_factory.py`
- `reports/diff_report.py` - Feature #31

**Severity & Scoring:**
- `severity/critical.py`
- `severity/high.py`
- `severity/medium.py`
- `severity/low.py`
- `severity/triage.py`
- `severity/validate.py`
- `severity/report_template.py`
- `severity/complete_report.py`
- `severity/confidence_scoring.py` - Feature #18
- `severity/cvss_calculator.py` - Feature #2

---

### 🔗 Yusuf Sanusi - Frontend Dev

**API Integration:**
- `frontend/src/api.js`
- `backend/routes/audit_file.py`
- `backend/routes/audit_chain.py`

**Tools:**
- `tools/http_probe.py`
- `tools/code_scanner.py`
- `tools/pattern_matcher.py`
- `tools/payload_generator.py`
- `tools/diff_analyzer.py` - Feature #31
- `tools/cvss_scorer.py`
- `tools/regex_scanner.py`
- `tools/tool_loader.py`
- `tools/test_generator.py` - Feature #29

**Sessions:**
- `sessions/session_manager.py`
- `sessions/context_manager.py`
- `sessions/hunt_session.py`
- `sessions/secure_session.py`
- `sessions/session_store.py`
- `sessions/session_loader.py`
- `sessions/session_parser.py`
- `sessions/session_factory.py`
- `sessions/audit_session.py` - Feature #16

**Tasks:**
- `tasks/task_definitions.py`
- `tasks/task_templates.py`
- `tasks/task_loader.py`
- `tasks/task_executor.py`
- `tasks/task_scheduler.py`
- `tasks/task_queue.py`
- `tasks/task_result.py`
- `tasks/task_history.py`
- `tasks/agent_task.py` - Feature #40

---

### 📋 Abubakar Adamu - Product & QA

**Configuration:**
- `config/settings.json`
- `config/models.json`
- `config/session.json`
- `config/providers.json`
- `config/hunts.json`
- `config/chains.json`
- `config/tools.json`
- `config/severity.json`
- `config/chains_config.json` - Feature #13

**Validation:**
- `validations/validations.py`
- `validations/sanitizers.py`
- `validations/input_validator.py`
- `validations/output_validator.py`
- `validations/schema_validator.py`
- `validations/payload_validator.py`
- `validations/regex_validator.py`
- `validations/validator_factory.py`

**Storage:**
- `storage/storage.py`
- `storage/cache.py`
- `storage/file_storage.py`
- `storage/database.py`
- `storage/key_value.py`
- `storage/blob_storage.py`
- `storage/persistence.py`
- `storage/storage_factory.py`
- `storage/audit_history.py` - Feature #16

**Documentation:**
- `docs/ARCHITECTURE.md`
- `docs/API_SPEC.md`
- `docs/DEPLOYMENT.md`
- `rules/detection_rules.md`
- `rules/payload_rules.md`
- `rules/bypass_rules.md`
- `rules/sqli_rules.md`
- `rules/xss_rules.md`
- `rules/rce_rules.md`
- `rules/ssrf_rules.md`
- `rules/idor_rules.md`
- `rules/auth_rules.md`
- `rules/reentrancy_rules.md`
- `rules/access_control_rules.md`
- `rules/defi_pattern_rules.md`

**CI/CD (Roadmap):**
- `ci-cd/github_action.py` - Feature #39
- `ci-cd/gitlab_ci.py`
- `ci-cd/jenkins.py`
- `ci-cd/pipeline_config.py`
- `ci-cd/action_yaml.py`

**VS Code Extension (Roadmap):**
- `vscode-extension/package.json` - Feature #38
- `vscode-extension/extension.js`
- `vscode-extension/audit_provider.js`

---

## Module Ownership Summary

| Module | Owner | Files |
|--------|-------|-------|
| `providers/` | **Peace** | 12 |
| `integrations/` | **Peace** | 12 |
| `models/` | **Peace** | 8 |
| `system-prompt/` | **Peace** | 9 |
| `backend/` | **Peace** | 10 |
| `runtime/` | **Peace** | 9 |
| `core/` | **Peace** | 8 |
| `vuln-detection/` | Joel | 12 |
| `blockchain/` | Joel | 10 |
| `solidity-analysis/` | Joel | 10 |
| `audit-engine/` | Joel | 10 |
| `chains/` | Joel | 10 |
| `exploitation/` | Joel | 9 |
| `defi-patterns/` | Joel | 8 |
| `sample_contracts/` | Joel | 7 |
| `frontend/src/components/` | Mayowa | 10 |
| `reports/` | Mayowa | 9 |
| `severity/` | Mayowa | 10 |
| `frontend/` | Mayowa/Yusuf | 2 |
| `tools/` | Yusuf | 9 |
| `sessions/` | Yusuf | 9 |
| `tasks/` | Yusuf | 9 |
| `config/` | Abubakar | 9 |
| `validations/` | Abubakar | 8 |
| `storage/` | Abubakar | 9 |
| `docs/` | Abubakar | 3 |
| `rules/` | Abubakar | 12 |
| `ci-cd/` | Abubakar | 5 |
| `vscode-extension/` | Abubakar | 3 |

---

## Workflow

1. **Daily Standup** - Share progress on assigned tasks
2. **Code Review** - Push to branch, tag reviewer
3. **Testing** - Abubakar tests each module before merge
4. **Documentation** - Update docs as you go

---

*Team SoliGuard - GDG Abuja × Build with AI Sprint*
*TCP (The Coding Peace) Ecosystem*
*SoliGuard v1.0 - 40 Features*