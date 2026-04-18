#!/usr/bin/env python3
"""
Solidify Main Entry Point
Web3 Smart Contract Security Auditor

Author: Peace Stephen (Tech Lead)
Description: Main CLI entry point with REPL, argument parsing and module integration
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

# Disable verbose logging - only show errors
logging.basicConfig(level=logging.ERROR, format="%(message)s")
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("httpcore").setLevel(logging.ERROR)
logging.getLogger("providers").setLevel(logging.ERROR)

# ============================================================================
# MODULE IMPORTS - All integrated modules
# Note: Some modules use hyphens in directory names - use importlib for those
# ============================================================================

# Models - Security model registry and configurations (works)
from models import (
    SolidifyModel,
    SecurityFocus,
    ModelProvider,
    get_model,
    list_all_models,
    get_system_prompt,
    AVAILABLE_MODELS,
)

# Hunts - Vulnerability hunters (select working ones)
from hunts import (
    reentrancy_hunter,
    access_control_hunter,
    oracle_manipulation_hunter,
    # flash_loan_hunter,  # has dataclass issue
    front_running_hunter,
    centralization_hunter,
    integer_overflow_hunter,
    arbitrary_call_hunter,
)

# Chains - Audit chains (skip - has syntax errors)
# from chains import reentrancy_scan, access_control_scan, full_audit, overflow_scan

# Providers - AI providers (works)
from providers import ProviderType
from providers.provider_factory import create_provider

# Rules - Detection rules (has syntax errors, skip for now)
vulnerability_rules = detection_rules = security_rules = None

# Reports - Report generation
from reports import report_generator, report_formatter, markdown_reporter

# Validations - Input/output validation
from validations import (
    input_validator,
    output_validator,
    payload_validator,
    validate_contract_input,
    validate_json_input,
    validate_file_path,
)

# Vuln-Detection - Detection engine (dir is vuln-detection with hyphen)
vuln_detection = None
try:
    from vuln_detection import (
        Severity,
        VulnerabilityType,
        VulnerabilityFinding,
        DetectionResult,
        ScanConfiguration,
        scan_contract,
        get_detector_count,
        get_supported_vulnerabilities,
    )
except Exception as e:
    pass

# Context-Management (has hyphen in dir name)
context_management = None
context_loader = None
context_saver = None

# Integrations (has hyphen)
integrations = None
llm_client = None
provider_bridge = None
tool_caller = None

# Storage (has hyphen)
storage = None
persistence = None
key_value = None
cache = None

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
    print("""
 ███╗   ██╗ ██████╗ ██████╗ ███████╗    ███████╗ █████╗  ██████╗ ███████╗
 ████╗  ██║██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██╔══██╗██╔════╝ ██╔════╝
 ██╔██╗ ██║██║   ██║██████╔╝█████╗      █████╗  ███████║██║  ███╗█████╗  
 ██║╚██╗██║██║   ██║██╔══██╗██╔══╝      ██╔══╝  ██╔══██║██║   ██║██╔══╝  
 ██║ ╚████║╚██████╔╝██║  ██║███████╗    ██║     ██║  ██║╚██████╔╝███████╗
 ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

               ██████╗  █████╗ ██████╗ ███████╗
               ██╔══██╗██╔══██╗██╔══██╗██╔════╝
               ██████╔╝███████║██████╔╝█████╗  
               ██╔══██╗██╔══██║██╔══██╗██╔══╝  
               ██████╔╝██║  ██║██║  ██║███████╗
               ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

                                    S O L I D I F Y
""")

    print("""
╔═══════════════════════════════════════════════════════════════╗
║                    SOLIGUARD COMMANDS                         ║
╠═══════════════════════════════════════════════════════════════╣
║  CORE COMMANDS:                                               ║
║  • audit <file>      - Audit a Solidity contract              ║
║  • hunt --file <f>  - Hunt for vulnerabilities                ║
║  • ask <question>   - Ask security questions                  ║
║  • scan <code>      - Quick vulnerability scan               ║
║                                                                       ║
║  UTILITY:                                                     ║
║  • help, ?          - Show this help message                 ║
║  • version          - Show version info                       ║
║  • providers        - List available providers                 ║
║  • clear            - Clear screen                           ║
║  • exit, quit, q    - Exit REPL                              ║
╚═══════════════════════════════════════════════════════════════╝
""")

    print("\n[Ready] Type 'help' for commands, 'exit' to quit\n")

    current_model = "minimaxai/minimax-m2.5"
    current_provider = "nvidia"

    while True:
        try:
            cmd = input(f"\nSolidify [{current_model.split('/')[-1]}]> ").strip()

            if not cmd:
                continue

            parts = cmd.split()
            command = parts[0].lower() if parts else ""
            args_str = " ".join(parts[1:]) if len(parts) > 1 else ""

            if command in ["exit", "quit", "q"]:
                print("\n[+] Goodbye! Stay secure.")
                break

            elif command in ["help", "?"]:
                print("""
Commands:
  audit <file.sol>       - Audit contract
  hunt --file <file>     - Hunt vulnerabilities  
  ask <question>         - Ask security question
  scan <code>            - Quick scan
  version                - Show version
  providers              - List providers
  clear                  - Clear screen
  exit/quit              - Exit
""")

            elif command == "clear":
                print("""
╔═══════════════════════════════════════════════════════════════╗
║   SoliGuard - Web3 Security Auditor - REPL Mode                 ║
╚═══════════════════════════════════════════════════════════════╝
""")

            elif command == "version":
                print(f"\n{APP_NAME} v{VERSION}")
                print(DESCRIPTION)

            elif command == "providers":
                from providers import ProviderType

                print(f"\nAvailable: {', '.join([p.value for p in ProviderType])}")

            elif command == "hunt":
                if "--file" in args_str or "-f" in args_str:
                    # Extract file
                    parts = args_str.split()
                    for i, p in enumerate(parts):
                        if p in ["--file", "-f"] and i + 1 < len(parts):
                            asyncio.run(
                                cmd_hunt_advanced(
                                    argparse.Namespace(
                                        file=parts[i + 1],
                                        url=None,
                                        address=None,
                                        model=current_model,
                                        provider=current_provider,
                                        task=None,
                                        no_stream=False,
                                        poc=False,
                                        patch=False,
                                    )
                                )
                            )
                            break
                elif "ask" in args_str:
                    question = args_str.replace("ask", "").strip()
                    if question:
                        asyncio.run(
                            cmd_ask(
                                argparse.Namespace(
                                    ask=question,
                                    provider=current_provider,
                                    model=current_model,
                                )
                            )
                        )
                else:
                    print("Usage: hunt --file <contract.sol> or hunt ask 'question'")

            elif command == "ask":
                if args_str:
                    asyncio.run(
                        cmd_ask(
                            argparse.Namespace(
                                ask=args_str,
                                provider=current_provider,
                                model=current_model,
                            )
                        )
                    )
                else:
                    print("Usage: ask <question>")

            elif command == "audit":
                if args_str:
                    asyncio.run(
                        cmd_audit(
                            argparse.Namespace(
                                file=args_str,
                                contract_code=None,
                                chain="ethereum",
                                provider=current_provider,
                                exploits=False,
                            )
                        )
                    )
                else:
                    print("Usage: audit <file.sol>")

            elif command == "scan":
                if args_str:
                    print(f"[Info] Scanning code...")
                else:
                    print("Usage: scan <contract_code>")

            else:
                print(f"[Error] Unknown: {command}. Type 'help' for commands.")

        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n\n[!] Use 'exit' to quit")
        except Exception as e:
            print(f"[Error] {e}")


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

    # No command = start REPL by default
    if not args.command:
        start_repl(args)
        return

    # Show help if --help
    if args.command == "help" or args.command == "help":
        print("""
 ███╗   ██╗ ██████╗ ██████╗ ███████╗    ███████╗ █████╗  ██████╗ ███████╗
 ████╗  ██║██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██╔══██╗██╔════╝ ██╔════╝
 ██╔██╗ ██║██║   ██║██████╔╝█████╗      █████╗  ███████║██║  ███╗█████╗  
 ██║╚██╗██║██║   ██║██╔══██╗██╔══╝      ██╔══╝  ██╔══██║██║   ██║██╔══╝  
 ██║ ╚████║╚██████╔╝██║  ██║███████╗    ██║     ██║  ██║╚██████╔╝███████╗
 ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

               ██████╗  █████╗ ██████╗ ███████╗
               ██╔══██╗██╔══██╗██╔══██╗██╔════╝
               ██████╔╝███████║██████╔╝█████╗  
               ██╔══██╗██╔══██║██╔══██╗██╔══╝  
               ██████╔╝██║  ██║██║  ██║███████╗
               ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

        ███████╗██████╗  ██████╗ ██████╗ ████████╗███████╗███╗   ███╗
        ██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝████╗ ████║
        █████╗  ██████╔╝██║   ██║██████╔╝   ██║   █████╗  ██╔████╔██║
        ██╔══╝  ██╔══██╗██║   ██║██╔══██╗   ██║   ██╔══╝  ██║╚██╔╝██║
        ███████╗██║  ██║╚██████╔╝██║  ██║   ██║   ███████╗██║ ╚═╝ ██║
        ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
                                    S O L I D I F Y
""")
        parser.print_help()
        return

    # Route commands
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
