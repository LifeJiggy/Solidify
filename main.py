#!/usr/bin/env python3
"""
Solidify Main Entry Point
Web3 Smart Contract Security Auditor

Author: Peace Stephen (Tech Lead)
Description: Main CLI entry point with REPL and argument parsing
"""

import asyncio
import argparse
import logging
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

VERSION = "1.0.0"
APP_NAME = "Solidify"
DESCRIPTION = "Web3 Smart Contract Security Auditor"


# ============================================================================
# CLI Commands
# ============================================================================


def cmd_audit(args: argparse.Namespace) -> None:
    """Run code audit using provider"""
    from providers.provider_factory import create_provider

    provider = create_provider(args.provider or "nvidia")
    if not provider:
        print("Error: Failed to create provider")
        return

    contract_code = ""
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                contract_code = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    elif args.contract_code:
        contract_code = args.contract_code

    if not contract_code:
        print("Error: No contract code provided")
        return

    import asyncio

    result = asyncio.run(provider.generate(contract_code))

    if hasattr(result, "content"):
        print(result.content)
    else:
        print(result)


def cmd_hunt(args: argparse.Namespace) -> None:
    """Run vulnerability hunt - Web3 Smart Contract Security"""

    # Handle ask mode - ask security questions directly
    if args.ask:
        asyncio.run(cmd_hunt_ask(args))
        return

    # Run Web3 Solidity hunt
    if args.url or args.file or args.address:
        asyncio.run(cmd_hunt_advanced(args))
    else:
        print("SoliGuard Hunt - Web3 Smart Contract Security Auditor")
        print("")
        print("Usage:")
        print(
            "  python main.py hunt --file <contract.sol>                    # Analyze Solidity file"
        )
        print(
            "  python main.py hunt --url <url>                              # Fetch from URL"
        )
        print(
            "  python main.py hunt --address <addr> --chain ethereum        # On-chain analysis"
        )
        print(
            "  python main.py hunt --ask 'how does reentrancy work?'        # Ask question"
        )
        print("")
        print("Options:")
        print("  --poc          Generate proof-of-concept exploits")
        print("  --patch        Generate secure patch recommendations")
        print("  --type <type>  Vulnerability type (reentrancy, overflow, etc)")
        print("  -p <provider>  Provider (qwen, nvidia, openai, anthropic)")
        print("  -m <model>     Model to use")


async def cmd_hunt_ask(args: argparse.Namespace) -> None:
    """Handle ask mode - answer security questions"""

    provider_name = args.provider or "qwen"
    question = args.ask

    print(f"\n{'=' * 60}")
    print(f"  SoliGuard Ask Mode")
    print(f"{'=' * 60}")
    print(f"  Provider: {provider_name}")
    print(f"  Question: {question}")
    print(f"{'=' * 60}\n")

    from providers.provider_factory import create_provider

    provider = create_provider(provider_name)

    if not provider:
        print(f"  [ERROR] Failed to create provider: {provider_name}")
        return

    # Use system prompt from hunting_prompt.py
    prompt = f"""You are a smart contract security expert at SoliGuard. Answer this question thoroughly:

Question: {question}

Provide a detailed explanation focusing on:
1. What the vulnerability/concept is
2. How to identify it in Solidity code
3. How to exploit it (for educational purposes)
4. How to fix and secure against it
5. Real-world examples if relevant

Be specific to Web3/Solidity context."""

    try:
        response = await provider.generate(prompt)

        if hasattr(response, "content"):
            print(response.content)
        elif isinstance(response, dict):
            print(response.get("content", str(response)))
        else:
            print(response)
    except Exception as e:
        print(f"  [ERROR] {e}")


async def cmd_hunt_advanced(args: argparse.Namespace) -> None:
    """Advanced hunt command with URL, model, task and streaming support"""
    import sys
    import io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    from providers import create_unified_provider, ProviderType
    from providers.streaming import create_streaming_processor
    from providers.logging import create_logger
    from providers.formatter import create_console_display

    provider_name = args.provider or "nvidia"
    model = args.model or "nvidia/llama-3.1-nemotron-70b-instruct"
    task = (
        args.task
        or "Find CRITICAL/HIGH security vulnerabilities in this smart contract"
    )

    print(f"\n{'=' * 60}")
    print(f"  Solidify Hunt Mode")
    print(f"{'=' * 60}")
    print(f"  Provider: {provider_name}")
    print(f"  Model: {model}")
    print(f"  Task: {task}")
    if args.url:
        print(f"  URL: {args.url}")
    if args.file:
        print(f"  File: {args.file}")
    print(f"{'=' * 60}\n")

    contract_code = ""

    if args.url:
        print(f"  [FETCHING] Fetching content from {args.url}...")
        try:
            import httpx

            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(args.url)
                if response.status_code == 200:
                    contract_code = response.text
                    print(f"  [OK] Fetched {len(contract_code)} characters")
                else:
                    print(f"  [ERROR] Failed to fetch: HTTP {response.status_code}")
                    return
        except Exception as e:
            print(f"  [ERROR] Error fetching URL: {e}")
            return
    elif args.file:
        print(f"  [READING] Reading file {args.file}...")
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                contract_code = f.read()
            print(f"  [OK] Read {len(contract_code)} characters")
        except Exception as e:
            print(f"  [ERROR] Error reading file: {e}")
            return
    elif args.code:
        contract_code = args.code
        print(f"  [OK] Using provided code ({len(contract_code)} chars)")

    if not contract_code:
        print("  [ERROR] No contract code provided")
        return

    stream = not args.no_stream

    if stream:
        print(f"\n  >> STREAMING MODE - Live output\n")

        stream_logger = create_logger()
        stream_logger.log_start(provider_name, model, 1)

        display = create_console_display(provider_name, model)
        display.start_stream(provider_name, model)

        try:
            provider_type = (
                ProviderType(provider_name.lower())
                if provider_name.lower() in [p.value for p in ProviderType]
                else ProviderType.NVIDIA
            )

            from providers.provider_factory import create_provider

            provider = create_provider(provider_name)

            if not provider:
                print(f"  ❌ Failed to create provider: {provider_name}")
                return

            streaming_processor = create_streaming_processor(provider_name)

            prompt = f"""You are a smart contract security auditor. Analyze the following code for CRITICAL and HIGH severity vulnerabilities.

Task: {task}

Contract Code:
```
{contract_code[:50000]}
```

Provide a detailed security analysis focusing ONLY on CRITICAL and HIGH severity vulnerabilities. For each finding, include:
1. Vulnerability type
2. Severity (CRITICAL/HIGH)
3. Location (line numbers if available)
4. Description
5. Proof of concept exploit (if possible)

If no CRITICAL/HIGH vulnerabilities found, explicitly state "No CRITICAL/HIGH vulnerabilities found."

Begin your analysis:"""

            stream_gen = provider.generate_stream(prompt)

            full_response = ""
            chunk_count = 0

            async for chunk in stream_gen:
                if isinstance(chunk, bytes):
                    chunk = chunk.decode("utf-8")

                chunk = chunk.strip()
                if not chunk:
                    continue

                if chunk.startswith("data: "):
                    chunk = chunk[6:]

                if chunk == "[DONE]":
                    break

                try:
                    import json

                    data = json.loads(chunk)
                    if "choices" in data and data["choices"]:
                        content = data["choices"][0].get("delta", {}).get("content", "")
                        if content:
                            full_response += content
                            chunk_count += 1
                            display.add_chunk(content)
                            stream_logger.log_chunk(chunk, provider_name, chunk_count)
                except json.JSONDecodeError:
                    full_response += chunk
                    chunk_count += 1
                    display.add_chunk(chunk)

            display.end_stream(len(full_response), 0)
            stream_logger.log_complete(
                provider_name, model, chunk_count, len(full_response), 0
            )

            print(
                f"\n  ✅ Hunt complete - {chunk_count} chunks, {len(full_response)} chars"
            )

            if full_response:
                print(f"\n{'=' * 60}")
                print(f"  ANALYSIS RESULT")
                print(f"{'=' * 60}\n")
                print(full_response[:5000])
                if len(full_response) > 5000:
                    print(f"\n  ... (truncated, full result saved)")

        except Exception as e:
            display.show_error(str(e))
            stream_logger.log_error(str(e), provider_name, model)
            print(f"\n  ❌ Error: {e}")
    else:
        print(f"\n  🔄 Streaming disabled - using standard mode\n")

        try:
            from providers.provider_factory import create_provider

            provider = create_provider(provider_name)

            prompt = f"""You are a smart contract security auditor. Analyze the following code for CRITICAL and HIGH severity vulnerabilities.

Task: {task}

Contract Code:
```
{contract_code[:50000]}
```

Provide a detailed security analysis focusing ONLY on CRITICAL and HIGH severity vulnerabilities."""

            response = await provider.generate(prompt)

            if hasattr(response, "content"):
                print(response.content)
            elif isinstance(response, dict):
                print(response.get("content", str(response)))
            else:
                print(response)

        except Exception as e:
            print(f"  [ERROR] {e}")


def cmd_scan(args: argparse.Namespace) -> None:
    """Quick vulnerability scan"""
    print("Scanning not fully implemented - use hunt command instead")
    print("Available: python main.py hunt --file <file.sol>")


def cmd_report(args: argparse.Namespace) -> None:
    """Generate audit report"""
    from system_prompt.report_prompt import ReportPrompt, ReportData

    prompt = ReportPrompt()
    data = ReportData(
        contract_name=args.contract_name or "Contract",
        vulnerabilities=args.findings or [],
        risk_score=0.0,
        summary="Report generated via CLI",
    )
    report = prompt.build_markdown(data)
    print(report)


def cmd_session_list(args: argparse.Namespace) -> None:
    """List sessions"""
    from sessions.session_manager import list_all_sessions

    sessions = list_all_sessions()
    print(f"Total sessions: {len(sessions)}")
    for s in sessions:
        print(f"  {s.get('session_id')}: {s.get('status')}")


def cmd_provider_list(args: argparse.Namespace) -> None:
    """List providers"""
    from providers import ProviderType

    providers = [p.value for p in ProviderType]
    print(f"Available providers: {', '.join(providers)}")


def cmd_version(args: argparse.Namespace) -> None:
    """Show version"""
    print(f"{APP_NAME} v{VERSION}")
    print(DESCRIPTION)


# ============================================================================
# REPL
# ============================================================================


def start_repl(args: argparse.Namespace) -> None:
    """Start interactive REPL"""
    print("=" * 60)
    print("  Solidify REPL v1.0")
    print("  Web3 Smart Contract Security Auditor")
    print("=" * 60)
    print()
    print("Commands:")
    print("  audit <code>   - Audit contract code")
    print("  hunt <code>   - Hunt vulnerabilities")
    print("  scan <code>   - Quick scan")
    print("  help          - Show help")
    print("  exit          - Exit REPL")
    print()

    # Simple REPL loop
    while True:
        try:
            cmd = input("Solidify> ").strip()
            if not cmd:
                continue
            if cmd in ["exit", "quit", "q"]:
                break
            if cmd == "help" or cmd == "?":
                print("Commands: audit, hunt, scan, help, exit")
                continue
            if cmd.startswith("audit "):
                code = cmd[6:]
                print(f"Auditing contract... ({len(code)} chars)")
                print("Use --code argument for full audit")
                continue
            if cmd.startswith("hunt "):
                print("Hunting vulnerabilities...")
                continue
            if cmd.startswith("scan "):
                print("Scanning...")
                continue
            print(f"Unknown command: {cmd}")
        except EOFError:
            break
        except KeyboardInterrupt:
            print()
            break

    print("Goodbye!")


# ============================================================================
# Parser
# ============================================================================


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s audit --code "contract code here"
  %(prog)s audit --file contract.sol --chain ethereum
  %(prog)s hunt --code "contract code"
  %(prog)s scan --code "contract code"
  %(prog)s repl --provider gemini
  %(prog)s repl --script audit.sol

Other commands:
  %(prog)s session list
  %(prog)s provider list
  %(prog)s version
        """,
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Audit smart contract")
    audit_parser.add_argument("--code", type=str, help="Contract code")
    audit_parser.add_argument("-f", "--file", type=str, help="Contract file")
    audit_parser.add_argument(
        "--chain", type=str, default="ethereum", help="Blockchain chain"
    )
    audit_parser.add_argument(
        "-p", "--provider", type=str, default="gemini", help="AI provider"
    )
    audit_parser.add_argument(
        "--exploits", action="store_true", help="Include exploit PoCs"
    )

    # Hunt command - Web3 + Web2 Vulnerability Hunt
    hunt_parser = subparsers.add_parser(
        "hunt", help="Hunt for vulnerabilities (Web3 Solidity + Web2 JS)"
    )

    # Input sources
    hunt_parser.add_argument("--target", "-t", help="Target URL or contract address")
    hunt_parser.add_argument("--url", help="Target URL to fetch contract/JS from")
    hunt_parser.add_argument("--file", "-f", help="Local file to scan (.sol, .js, .ts)")
    hunt_parser.add_argument("--folder", help="Folder with files to scan")
    hunt_parser.add_argument("--address", help="Contract address for on-chain analysis")
    hunt_parser.add_argument(
        "--js", help="JavaScript file to analyze for vulnerabilities"
    )

    # Analysis options
    hunt_parser.add_argument(
        "--task", help="Hunt task (e.g., 'Find reentrancy', 'Exploit SQLi')"
    )
    hunt_parser.add_argument(
        "--type",
        help="Vulnerability type: reentrancy, overflow, access_control, sqli, xss, ssrf",
    )
    hunt_parser.add_argument(
        "--chain", default="ethereum", help="Blockchain (ethereum, bsc, polygon)"
    )
    hunt_parser.add_argument("--model", "-m", help="Model to use")
    hunt_parser.add_argument(
        "--provider", "-p", default="qwen", help="AI provider (nvidia, qwen, openai)"
    )

    # Modes
    hunt_parser.add_argument(
        "--no-stream", action="store_true", help="Disable streaming"
    )
    hunt_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    hunt_parser.add_argument(
        "--aggressive", "-a", action="store_true", help="Aggressive deep scan"
    )

    # Analysis features
    hunt_parser.add_argument("--poc", action="store_true", help="Generate PoC exploits")
    hunt_parser.add_argument(
        "--patch", action="store_true", help="Generate secure patches"
    )
    hunt_parser.add_argument(
        "--explain", action="store_true", help="Explain vulnerability concepts"
    )
    hunt_parser.add_argument(
        "--exploit", action="store_true", help="Show how to exploit"
    )
    hunt_parser.add_argument(
        "--analyze", action="store_true", help="Deep analysis mode"
    )
    hunt_parser.add_argument(
        "--report", action="store_true", help="Generate full report"
    )
    hunt_parser.add_argument(
        "--ext", default=".sol,.js", help="File extensions (comma-separated)"
    )

    # Ask mode
    hunt_parser.add_argument(
        "--ask", help="Ask security question (e.g., 'how to exploit SQL injection?')"
    )

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Quick vulnerability scan")
    scan_parser.add_argument("--code", type=str, required=True, help="Contract code")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report")
    report_parser.add_argument(
        "--findings", type=eval, default=[], help="Findings list"
    )
    report_parser.add_argument(
        "-f", "--format", type=str, default="markdown", help="Report format"
    )
    report_parser.add_argument("-n", "--name", type=str, help="Contract name")

    # REPL command
    repl_parser = subparsers.add_parser("repl", help="Start interactive REPL")
    repl_parser.add_argument(
        "-p", "--provider", type=str, default="gemini", help="AI provider"
    )
    repl_parser.add_argument("-s", "--script", type=str, help="Script file to run")

    # Session commands
    session_parser = subparsers.add_parser("session", help="Session management")
    session_sub = session_parser.add_subparsers(dest="session_action")
    session_sub.add_parser("list", help="List sessions")

    # Provider commands
    provider_parser = subparsers.add_parser("provider", help="Provider management")
    provider_sub = provider_parser.add_subparsers(dest="provider_action")
    provider_sub.add_parser("list", help="List providers")

    # Version command
    version_parser = subparsers.add_parser("version", help="Show version")

    return parser


# ============================================================================
# Main
# ============================================================================


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Handle no command
    if not args.command:
        start_repl(args)
        return

    # Set debug mode
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Route commands
    if args.command == "audit":
        cmd_audit(args)
    elif args.command == "hunt":
        if args.url or args.file or args.code:
            asyncio.run(cmd_hunt_advanced(args))
        else:
            cmd_hunt(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "repl":
        start_repl(args)
    elif args.command == "session":
        if args.session_action == "list":
            cmd_session_list(args)
    elif args.command == "provider":
        if args.provider_action == "list":
            cmd_provider_list(args)
    elif args.command == "version":
        cmd_version(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
