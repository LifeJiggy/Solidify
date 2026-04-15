## 📁 Repository Structure

```
solidify/
├── backend/                          # FastAPI backend
│   ├── main.py                       # FastAPI app entry point
│   ├── routes/
│   │   ├── audit_code.py             # POST /audit/code
│   │   ├── audit_file.py             # POST /audit/file
│   │   ├── audit_chain.py            # POST /audit/chain
│   │   └── audit_stream.py           # SSE real-time streaming
│   ├── core/
│   │   ├── gemini_client.py          # Gemini API wrapper
│   │   ├── prompt_engine.py          # All prompt templates
│   │   ├── vuln_taxonomy.py          # Vuln definitions
│   │   ├── pdf_generator.py          # PDF export (reportlab)
│   │   └── cvss_scorer.py            # CVSS 3.1 scoring
│   └── utils/
│       └── chain_fetcher.py          # Etherscan + Sourcify
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                         # React frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── CodeEditor.jsx        # Monaco editor (Solidity)
│   │   │   ├── FileUpload.jsx        # Drag & drop .sol
│   │   │   │   └── multi_upload.py   # Multi-file .zip upload
│   │   │   ├── ChainInput.jsx        # Contract address input
│   │   │   │   └── chain_selector.py # Multi-chain selector
│   │   │   ├── AuditReport.jsx       # Side-by-side diff
│   │   │   ├── SeverityBadge.jsx     # CRITICAL/HIGH/MEDIUM/LOW
│   │   │   ├── ConfidenceScore.jsx  # AI confidence %
│   │   │   └── NaturalLanguageQuery.jsx # Chat input
│   │   ├── App.jsx
│   │   ├── api.js
│   │   └── styles/
│   └── package.json
│
│
├── sample_contracts/                 # Demo contracts
│   ├── clean_contract.sol
│   ├── reentrancy_vuln.sol
│   ├── overflow_vuln.sol
│   ├── access_control_vuln.sol
│   ├── flash_loan_vuln.sol
│   ├── nft_vuln.sol                  # NFT audit demo
│   └── defi_vuln.sol                 # DeFi protocol demo
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API_SPEC.md
│   └── DEPLOYMENT.md
│
├── runtime/                          # .py Process layer (9 files)
│   ├── loader.py
│   ├── repl.py
│   ├── executor.py
│   ├── session.py
│   ├── reporter.py
│   ├── runner.py
│   ├── parser.py
│   ├── factory.py
│   └── stream_handler.py             # SSE streaming
│
├── integrations/                     # .py LLM + tool bridges (12 files)
│   ├── llm_client.py
│   ├── tool_caller.py
│   ├── stream_handler.py
│   ├── ollama_bridge.py
│   ├── file_injector.py
│   ├── model_loader.py
│   ├── provider_bridge.py
│   ├── integration_factory.py
│   ├── anthropic_bridge.py          # BYOA
│   ├── openai_bridge.py              # BYOA
│   ├── nvidia_bridge.py              # BYOA
│   └── qwen_bridge.py                # BYOA
│
├── memory/                           # .py Memory management (8 files)
│   ├── memory.py
│   ├── context.py
│   ├── session_memory.py             # Audit history
│   ├── working_memory.py
│   ├── episodic_memory.py
│   ├── semantic_memory.py
│   ├── context_window.py
│   └── memory_loader.py
│
├── storage/                          # .py Storage layer (9 files)
│   ├── storage.py
│   ├── cache.py
│   ├── file_storage.py
│   ├── database.py
│   ├── key_value.py
│   ├── blob_storage.py
│   ├── persistence.py
│   ├── storage_factory.py
│   └── audit_history.py              # Persist audit history
│
├── validations/                      # .py Validation logic (8 files)
│   ├── validations.py
│   ├── sanitizers.py
│   ├── input_validator.py
│   ├── output_validator.py
│   ├── schema_validator.py
│   ├── payload_validator.py
│   ├── regex_validator.py
│   └── validator_factory.py
│
├── sessions/                         # .py Session management (9 files)
│   ├── session_manager.py
│   ├── context_manager.py
│   ├── hunt_session.py
│   ├── secure_session.py
│   ├── session_store.py
│   ├── session_loader.py
│   ├── session_parser.py
│   ├── session_factory.py
│   └── audit_session.py              # Audit session tracking
│
├── commands/                         # .py Command handlers (9 files)
│   ├── commands.py
│   ├── cli.py
│   ├── command_parser.py
│   ├── command_loader.py
│   ├── command_executor.py
│   ├── command_registry.py
│   ├── command_validator.py
│   ├── command_factory.py
│   └── audit_commands.py             # Audit-specific commands
│
├── exploitation/                     # .py Exploitation (Web3) (9 files)
│   ├── exploit_engine.py
│   ├── payload_generator.py          # PoC generator
│   ├── exploit_runner.py
│   ├── exploit_validator.py
│   ├── exploit_reporter.py
│   ├── exploit_parser.py
│   ├── exploit_loader.py
│   ├── exploit_store.py
│   └── reentrancy_poc.py             # Reentrancy PoC
│
├── reports/                          # .py Report generation (9 files)
│   ├── reporter.py
│   ├── report_generator.py
│   ├── report_formatter.py
│   ├── html_reporter.py
│   ├── markdown_reporter.py          # MD export
│   ├── pdf_reporter.py               # PDF export
│   ├── report_template.py
│   ├── report_factory.py
│   └── diff_report.py                # Contract diff report
│
├── chains/                           # .py Multi-step audit chains (10 files)
│   ├── full_audit.py
│   ├── code_audit.py
│   ├── bounty_chain.py
│   ├── reentrancy_scan.py
│   ├── overflow_scan.py
│   ├── access_control_scan.py
│   ├── gas_optimization.py
│   ├── layer2_audit.py
│   ├── multi_vuln_chain.py           # Vulnerability chaining
│   └── defi_audit.py                 # DeFi protocol audit
│
├── core/                             # .py Orchestration (8 files)
│   ├── router.py
│   ├── orchestrator.py
│   ├── memory.py
│   ├── escalation.py
│   ├── session.py
│   ├── loader.py
│   ├── executor.py
│   └── reporter.py
│
├── tools/                            # .py Tool definitions (9 files)
│   ├── http_probe.py
│   ├── code_scanner.py
│   ├── pattern_matcher.py
│   ├── payload_generator.py
│   ├── diff_analyzer.py              # Contract diff
│   ├── cvss_scorer.py
│   ├── regex_scanner.py
│   ├── tool_loader.py
│   └── test_generator.py            # Foundry/Hardhat tests
│
├── providers/                        # .py Provider specs (12 files)
│   ├── anthropic.py                  # BYOA
│   ├── qwen.py                       # BYOA
│   ├── ollama.py                     # BYOA
│   ├── groq.py                       # BYOA
│   ├── nvidia.py                     # BYOA (NIM)
│   ├── openai.py                     # BYOA
│   ├── google.py                     # BYOA (Vertex)
│   ├── provider_factory.py
│   ├── provider_config.py
│   ├── provider_loader.py
│   ├── provider_registry.py
│   └── gemini.py                     # Default
│
├── config/                           # .json Config files (9 files)
│   ├── settings.json
│   ├── models.json
│   ├── session.json
│   ├── providers.json
│   ├── hunts.json
│   ├── chains.json
│   ├── tools.json
│   ├── severity.json
│   └── chains_config.json            # Multi-chain config
│
├── rules/                            # .md Detection rules (12 files)
│   ├── detection_rules.md
│   ├── payload_rules.md
│   ├── bypass_rules.md
│   ├── sqli_rules.md
│   ├── xss_rules.md
│   ├── rce_rules.md
│   ├── ssrf_rules.md
│   ├── idor_rules.md
│   ├── auth_rules.md
│   ├── reentrancy_rules.md
│   ├── access_control_rules.md
│   └── defi_pattern_rules.md
│
├── models/                           # .py Model definitions (8 files)
│   ├── claude_opus_4.py
│   ├── claude_opus_4_5.py
│   ├── qwen3_235b.py
│   ├── qwen3_security.py
│   ├── qwen3_coder.py
│   ├── qwen_vl.py
│   ├── ghost_local.py
│   └── model_registry.py
│
├── hunts/                            # .py Offensive operation specs
│   └── hunt_specs.py
│
├── severity/                         # .py Scoring + triage (10 files)
│   ├── critical.py
│   ├── high.py
│   ├── medium.py
│   ├── low.py
│   ├── triage.py
│   ├── validate.py
│   ├── report_template.py
│   ├── complete_report.py
│   ├── confidence_scoring.py         # AI confidence %
│   └── cvss_calculator.py
│
├── recon/                            # .py Recon pipeline (8 files)
│   ├── target_profiling.py
│   ├── endpoint_discovery.py
│   ├── param_fuzzing.py
│   ├── header_analysis.py
│   ├── js_analysis.py
│   ├── subdomain_enum.py
│   ├── tech_detection.py
│   └── service_enum.py
│
├── audit-engine/                     # .py Smart contract audit (10 files)
│   ├── scanner.py
│   ├── crawler.py
│   ├── injector.py
│   ├── fuzzer.py
│   ├── reporter.py
│   ├── plugin_manager.py
│   ├── config_loader.py
│   ├── scheduler.py
│   ├── multi_contract.py             # Multi-file project
│   └── project_zip.py               # .zip extraction
│
├── solidity-analysis/               # .py Solidity analysis (10 files)
│   ├── parser.py
│   ├── ast_analyzer.py
│   ├── taint_analysis.py
│   ├── control_flow.py
│   ├── data_flow.py
│   ├── call_graph.py
│   ├── gas_analysis.py              # Gas optimization
│   ├── decompiler.py
│   ├── cross_contract.py            # Cross-contract analysis
│   └── proxy_pattern.py             # Upgradeable proxy audit
│
├── vuln-detection/                  # .py Vulnerability detection (12 files)
│   ├── reentrancy_detector.py
│   ├── overflow_detector.py
│   ├── access_control_detector.py
│   ├── unchecked_call_detector.py
│   ├── front_run_detector.py
│   ├── timestamp_detector.py
│   ├── selfdestruct_detector.py
│   ├── dos_detector.py
│   ├── flash_loan_detector.py       # Flash loan surface
│   ├── sandwich_detector.py         # Sandwich attack
│   ├── oracle_manipulation_detector.py
│   └── wallet_drainer_detector.py
│
├── hooks/                            # .py Hook specs (9 files)
│   ├── pre_hooks.py
│   ├── post_hooks.py
│   ├── auth_hooks.py
│   ├── validation_hooks.py
│   ├── logging_hooks.py
│   ├── cleanup_hooks.py
│   ├── event_hooks.py
│   ├── custom_hooks.py
│   └── audit_hooks.py               # Audit lifecycle hooks
│
├── mcp/                              # .py MCP protocol specs (9 files)
│   ├── protocol.py
│   ├── handlers.py
│   ├── client.py
│   ├── server.py
│   ├── tools.py
│   ├── resources.py
│   ├── prompts.py
│   ├── transport.py
│   └── rest_api.py                  # REST API for external integration
│
├── skills/                           # .py Skill definitions (9 files)
│   ├── skill_registry.py
│   ├── custom_skills.py
│   ├── skill_loader.py
│   ├── skill_executor.py
│   ├── skill_validator.py
│   ├── skill_context.py
│   ├── skill_hooks.py
│   ├── skill_storage.py
│   └── audit_skills.py              # Audit-specific skills
│
├── system-prompt/                    # .py System prompt configs (9 files)
│   ├── base_prompt.py
│   ├── hunting_prompt.py
│   ├── recon_prompt.py
│   ├── exploit_prompt.py
│   ├── report_prompt.py
│   ├── repl_prompt.py
│   ├── chain_prompt.py
│   ├── context_prompt.py
│   └── natural_language_prompt.py   # Query system prompt
│
├── tasks/                            # .py Task definitions (9 files)
│   ├── task_definitions.py
│   ├── task_templates.py
│   ├── task_loader.py
│   ├── task_executor.py
│   ├── task_scheduler.py
│   ├── task_queue.py
│   ├── task_result.py
│   ├── task_history.py
│   └── agent_task.py                # Agent mode tasks
│
├── context-management/               # .py Context management (9 files)
│   ├── context.py
│   ├── context_loader.py
│   ├── context_saver.py
│   ├── context_parser.py
│   ├── context_manager.py
│   ├── context_factory.py
│   ├── context_validator.py
│   ├── context_storage.py
│   └── audit_context.py             # Audit session context
│
├── task-persistence/                 # .py Task persistence (9 files)
│   ├── task_persistence.py
│   ├── persistence_manager.py
│   ├── task_saver.py
│   ├── task_loader.py
│   ├── task_serializer.py
│   ├── task_backup.py
│   ├── task_restore.py
│   └── persistence_factory.py
│
├── blockchain/                       # .py Blockchain integration (10 files)
│   ├── provider.py
│   ├── etherscan_client.py
│   ├── sourcify_client.py
│   ├── rpc_client.py
│   ├── contract_fetcher.py
│   ├── abi_parser.py
│   ├── transaction_analyzer.py      # On-chain tx history
│   ├── block_explorer.py
│   ├── multi_chain.py               # Multi-chain support
│   └── ipfs_client.py               # IPFS source verification
│
├── defi-patterns/                    # .py DeFi protocol patterns (8 files)
│   ├── amm_pattern.py                # Uniswap V2/V3
│   ├── lending_pattern.py            # Aave, Compound
│   ├── yield_farming.py
│   ├── stablecoin.py
│   ├── governance_pattern.py         # DAO governance
│   ├── token_economics.py            # Tokenomics analysis
│   ├── erc_compliance.py            # ERC-20/721/1155
│   └── nft_pattern.py               # NFT contract audit
│
├── ci-cd/                            # .py CI/CD integration (5 files)
│   ├── github_action.py              # GitHub Actions
│   ├── gitlab_ci.py                 # GitLab CI
│   ├── jenkins.py
│   ├── pipeline_config.py
│   └── action_yaml.py                # YAML generator
│
├── vscode-extension/                 # VS Code extension (for roadmap)
│   ├── package.json
│   ├── extension.js
│   └── audit_provider.js
│
├── .gitignore
├── README.md
├── team.md
├── team-tasks.md
├── features.md                       # 40-Feature Roadmap
└── CHANGELOG.md
```

---

## 40-Feature Module Mapping

### 🔴 Critical Features → Modules
| Feature | Module |
|---------|--------|
| Core Solidity Audit Engine | `audit-engine/`, `backend/` |
| Severity Classification + CVSS | `severity/`, `backend/core/cvss_scorer.py` |
| Side-by-Side Patch Generation | `reports/`, `frontend/components/AuditReport.jsx` |
| File Upload Audit | `frontend/components/FileUpload.jsx`, `audit-engine/multi_contract.py` |
| On-Chain Contract Scan | `blockchain/`, `backend/utils/chain_fetcher.py` |
| PDF Audit Report Export | `reports/pdf_reporter.py`, `backend/core/pdf_generator.py` |

### 🟠 High Priority Features → Modules
| Feature | Module |
|---------|--------|
| Multi-Vuln Chaining | `chains/multi_vuln_chain.py` |
| PoC Exploit Generation | `exploitation/`, `tools/payload_generator.py` |
| Reentrancy Attack Sim | `vuln-detection/reentrancy_detector.py`, `exploitation/reentrancy_poc.py` |
| Overflow/Underflow PoC | `vuln-detection/overflow_detector.py` |
| Access Control PoC | `vuln-detection/access_control_detector.py` |
| Flash Loan Detection | `vuln-detection/flash_loan_detector.py` |
| Multi-Chain Support | `blockchain/multi_chain.py`, `frontend/components/chain_selector.py` |
| DeFi Pattern Recognition | `defi-patterns/` |
| NFT Audit Mode | `defi-patterns/nft_pattern.py` |
| Audit History | `memory/session_memory.py`, `storage/audit_history.py` |
| Natural Language Query | `system-prompt/natural_language_prompt.py`, `frontend/components/NaturalLanguageQuery.jsx` |
| Confidence Scoring | `severity/confidence_scoring.py`, `frontend/components/ConfidenceScore.jsx` |

### 🟡 Medium Priority Features → Modules
| Feature | Module |
|---------|--------|
| Gas Optimization | `solidity-analysis/gas_analysis.py`, `chains/gas_optimization.py` |
| Front-Running Detection | `vuln-detection/front_run_detector.py` |
| Sandwich Attack | `vuln-detection/sandwich_detector.py` |
| Oracle Manipulation | `vuln-detection/oracle_manipulation_detector.py` |
| Price Manipulation PoC | `exploitation/payload_generator.py` |
| Proxy Pattern Audit | `solidity-analysis/proxy_pattern.py` |
| Governance Detection | `defi-patterns/governance_pattern.py` |
| Token Economics | `defi-patterns/token_economics.py` |
| Cross-Contract Analysis | `solidity-analysis/cross_contract.py` |
| Sourcify + IPFS | `blockchain/sourcify_client.py`, `blockchain/ipfs_client.py` |
| Test Case Generator | `tools/test_generator.py` |
| Markdown Export | `reports/markdown_reporter.py` |
| Contract Diff | `tools/diff_analyzer.py`, `reports/diff_report.py` |
| Real-Time Streaming | `runtime/stream_handler.py`, `backend/routes/audit_stream.py` |
| Multi-File Project | `audit-engine/multi_contract.py`, `audit-engine/project_zip.py` |
| ERC Compliance | `defi-patterns/erc_compliance.py` |
| Tx History Scan | `blockchain/transaction_analyzer.py` |
| Wallet Drainer | `vuln-detection/wallet_drainer_detector.py` |

### 🟢 Roadmap Features → Modules
| Feature | Module |
|---------|--------|
| REST API | `mcp/rest_api.py` |
| VS Code Extension | `vscode-extension/` |
| CI/CD Integration | `ci-cd/` |
| Agent Mode | `tasks/agent_task.py`, `core/orchestrator.py` |