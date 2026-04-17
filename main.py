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
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Disable verbose logging
logging.basicConfig(level=logging.WARNING, format="%(message)s")
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

VERSION = "1.0.0"
APP_NAME = "Solidify"
DESCRIPTION = "Web3 Smart Contract Security Auditor"

if sys.platform == "win32":
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer)


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

    result = asyncio.run(provider.generate(contract_code))

    if hasattr(result, "content"):
        print(result.content)
    else:
        print(result)


def cmd_hunt(args: argparse.Namespace) -> None:
    """Run vulnerability hunt - Web3 Smart Contract Security"""
    if args.ask:
        asyncio.run(cmd_ask(args))
        return

    if args.url or args.file or args.address:
        asyncio.run(cmd_hunt_advanced(args))
    else:
        print("SoliGuard Hunt - Web3 Smart Contract Security Auditor")
        print("")
        print("Usage:")
        print("  python main.py hunt --file <contract.sol> -m minimaxai/minimax-m2.5")
        print("  python main.py hunt --url <url>")
        print("  python main.py hunt --ask 'how does reentrancy work?'")
        print("")
        print("Options:")
        print("  --poc          Generate proof-of-concept exploits")
        print("  --patch        Generate secure patch recommendations")
        print("  -p <provider>  Provider (nvidia, qwen, openai)")
        print("  -m <model>     Model to use")


async def cmd_ask(args: argparse.Namespace) -> None:
    """Answer security questions"""
    from providers.provider_factory import create_provider

    model = args.model or "minimaxai/minimax-m2.5"
    provider = create_provider(args.provider or "nvidia", model=model)
    if not provider:
        print(f"[ERROR] Cannot create provider")
        return

    prompt = f"""You are SoliGuard - a smart contract security expert. Answer this question:

{args.ask}

Provide a detailed technical answer."""

    try:
        response = await provider.generate(prompt)
        if response and hasattr(response, "content"):
            print(response.content)
    except Exception as e:
        print(f"[ERROR] {e}")


async def cmd_hunt_advanced(args: argparse.Namespace) -> None:
    """Advanced hunt with streaming"""
    provider_name = args.provider or "nvidia"
    model = args.model or "minimaxai/minimax-m2.5"

    print(f"\n{'=' * 50}")
    print(f"  SoliGuard - Smart Contract Auditor")
    print(f"  Model: {model}")
    if args.file:
        print(f"  File: {args.file}")
    print(f"{'=' * 50}\n")

    # Read contract
    contract_code = ""
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                contract_code = f.read()
            print(f"[OK] Loaded {len(contract_code)} chars\n")
        except Exception as e:
            print(f"[ERROR] {e}")
            return

    if not contract_code:
        print("[ERROR] No contract code")
        return

    from providers.provider_factory import create_provider

    provider = create_provider(provider_name, model=model)

    if not provider:
        print(f"[ERROR] Cannot create provider: {provider_name}")
        return

    prompt = f"""You are SoliGuard - a Web3 smart contract security auditor. Analyze this Solidity contract for CRITICAL and HIGH severity vulnerabilities.

Contract:
```solidity
{contract_code[:40000]}
```

Find and report:
1. Vulnerability name and severity
2. Location (function)
3. Description
4. Fix

If none, say "No CRITICAL/HIGH vulnerabilities found"."""

    try:
        print("\n[AI Response Stream]")
        print("-" * 40)

        full_response = ""
        async for chunk in provider.generate_stream(prompt):
            if isinstance(chunk, bytes):
                chunk = chunk.decode("utf-8", errors="replace")

            chunk = chunk.strip()
            if not chunk:
                continue

            if chunk.startswith("data: "):
                chunk = chunk[6:]

            if chunk == "[DONE]":
                break

            try:
                data = json.loads(chunk)
                if "choices" in data and data["choices"]:
                    content = data["choices"][0].get("delta", {}).get("content", "")
                    if content:
                        full_response += content
                        print(content, end="", flush=True)
            except json.JSONDecodeError:
                full_response += chunk
                print(chunk, end="", flush=True)

        print("\n" + "-" * 40)

    except Exception as e:
        print(f"\n[ERROR] {e}")


def cmd_scan(args: argparse.Namespace) -> None:
    """Quick vulnerability scan"""
    print("Scanning not fully implemented - use hunt command instead")
    print("Available: python main.py hunt --file <file.sol>")


def cmd_session_list(args: argparse.Namespace) -> None:
    """List sessions"""
    print("Session management not available")


def cmd_provider_list(args: argparse.Namespace) -> None:
    """List providers"""
    from providers import ProviderType

    providers = [p.value for p in ProviderType]
    print(f"Available providers: {', '.join(providers)}")


def cmd_version(args: argparse.Namespace) -> None:
    """Show version"""
    print(f"{APP_NAME} v{VERSION}")
    print(DESCRIPTION)


def start_repl(args: argparse.Namespace) -> None:
    """Start interactive REPL"""
    print("=" * 60)
    print("  Solidify REPL v1.0")
    print("  Web3 Smart Contract Security Auditor")
    print("=" * 60)
    print()
    print("Commands:")
    print("  hunt --file <file>   - Hunt vulnerabilities")
    print("  hunt --ask '?'       - Ask security question")
    print("  help                 - Show help")
    print("  exit                 - Exit REPL")
    print()

    while True:
        try:
            cmd = input("Solidify> ").strip()
            if not cmd:
                continue
            if cmd in ["exit", "quit", "q"]:
                break
            if cmd == "help" or cmd == "?":
                print("Commands: hunt, help, exit")
                continue
            if cmd.startswith("hunt "):
                print("Use: hunt --file <file.sol> or hunt --ask 'question'")
                continue
            print(f"Unknown command: {cmd}")
        except EOFError:
            break
        except KeyboardInterrupt:
            print()
            break
    print("Goodbye!")


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        "-p", "--provider", type=str, default="nvidia", help="AI provider"
    )
    audit_parser.add_argument(
        "--exploits", action="store_true", help="Include exploit PoCs"
    )

    # Hunt command
    hunt_parser = subparsers.add_parser("hunt", help="Hunt for vulnerabilities")
    hunt_parser.add_argument("--target", "-t", help="Target URL or contract address")
    hunt_parser.add_argument("--url", help="Target URL")
    hunt_parser.add_argument("--file", "-f", help="Local file to scan")
    hunt_parser.add_argument("--folder", help="Folder with files")
    hunt_parser.add_argument("--address", help="Contract address")
    hunt_parser.add_argument("--task", help="Hunt task")
    hunt_parser.add_argument("--type", help="Vulnerability type")
    hunt_parser.add_argument("--chain", default="ethereum", help="Blockchain")
    hunt_parser.add_argument(
        "--model", "-m", default="minimaxai/minimax-m2.5", help="Model"
    )
    hunt_parser.add_argument("--provider", "-p", default="nvidia", help="Provider")
    hunt_parser.add_argument(
        "--no-stream", action="store_true", help="Disable streaming"
    )
    hunt_parser.add_argument("--poc", action="store_true", help="Generate PoC")
    hunt_parser.add_argument("--patch", action="store_true", help="Generate patches")
    hunt_parser.add_argument("--ask", help="Ask security question")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Quick vulnerability scan")
    scan_parser.add_argument("--code", type=str, required=True, help="Contract code")

    # REPL command
    repl_parser = subparsers.add_parser("repl", help="Start interactive REPL")
    repl_parser.add_argument(
        "-p", "--provider", type=str, default="nvidia", help="AI provider"
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

    # Ask command - ask security questions
    ask_parser = subparsers.add_parser("ask", help="Ask security questions")
    ask_parser.add_argument("question", help="Question to ask")
    ask_parser.add_argument(
        "--model", "-m", default="minimaxai/minimax-m2.5", help="Model"
    )
    ask_parser.add_argument("-p", "--provider", default="nvidia", help="Provider")

    # Version command
    version_parser = subparsers.add_parser("version", help="Show version")

    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.command:
        # Default: show help or run hunt with default args
        print("SoliGuard - Web3 Smart Contract Security Auditor")
        print("Usage: python main.py hunt --file <contract.sol>")
        print("       python main.py ask 'What is reentrancy?'")
        print("       python main.py hunt --help")
        return

    if args.command == "ask":
        asyncio.run(
            cmd_ask(
                argparse.Namespace(
                    ask=args.question,
                    provider=args.provider,
                    model=args.model,
                )
            )
        )
        return

    if args.command == "audit":
        cmd_audit(args)
    elif args.command == "hunt":
        cmd_hunt(args)
    elif args.command == "scan":
        cmd_scan(args)
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
