#!/usr/bin/env python3
"""
SoliGuard Main Entry Point
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
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

VERSION = "1.0.0"
APP_NAME = "SoliGuard"
DESCRIPTION = "Web3 Smart Contract Security Auditor"


# ============================================================================
# CLI Commands
# ============================================================================

def cmd_audit(args: argparse.Namespace) -> None:
    """Run code audit"""
    from commands.commands import AuditCommand
    
    cmd = AuditCommand()
    result = asyncio.run(cmd.execute(
        code=args.contract_code or "",
        file=args.file or "",
        chain=args.chain or "ethereum",
        provider=args.provider or "gemini",
        include_exploits=args.exploits
    ))
    
    if result.success:
        print(result.output)
    else:
        print(f"Error: {result.error}", file=sys.stderr)
        sys.exit(1)


def cmd_hunt(args: argparse.Namespace) -> None:
    """Run vulnerability hunt"""
    from hunts.reentrancy_hunter import hunt_reentrancy
    
    findings = hunt_reentrancy(args.contract_code or "")
    print(f"Found {len(findings)} potential issues")
    for f in findings:
        print(f"  - {f.get('type')}: {f.get('description')}")


def cmd_scan(args: argparse.Namespace) -> None:
    """Quick vulnerability scan"""
    from vuln_detection.detector import VulnerabilityDetector
    
    detector = VulnerabilityDetector()
    findings = detector.scan(args.contract_code or "")
    print(f"Scan complete: {len(findings)} findings")


def cmd_report(args: argparse.Namespace) -> None:
    """Generate audit report"""
    from system_prompt.report_prompt import generate_report
    
    report = generate_report(
        findings=args.findings or [],
        format=args.format or "markdown",
        contract_name=args.contract_name or "Contract"
    )
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
    print("  SoliGuard REPL v1.0")
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
            cmd = input("soliguard> ").strip()
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
        """
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Debug mode"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Audit command
    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit smart contract"
    )
    audit_parser.add_argument(
        "--code",
        type=str,
        help="Contract code"
    )
    audit_parser.add_argument(
        "-f", "--file",
        type=str,
        help="Contract file"
    )
    audit_parser.add_argument(
        "--chain",
        type=str,
        default="ethereum",
        help="Blockchain chain"
    )
    audit_parser.add_argument(
        "-p", "--provider",
        type=str,
        default="gemini",
        help="AI provider"
    )
    audit_parser.add_argument(
        "--exploits",
        action="store_true",
        help="Include exploit PoCs"
    )
    
    # Hunt command
    hunt_parser = subparsers.add_parser(
        "hunt",
        help="Hunt for vulnerabilities"
    )
    hunt_parser.add_argument(
        "--code",
        type=str,
        required=True,
        help="Contract code"
    )
    hunt_parser.add_argument(
        "-t", "--type",
        type=str,
        default="reentrancy",
        help="Vulnerability type"
    )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Quick vulnerability scan"
    )
    scan_parser.add_argument(
        "--code",
        type=str,
        required=True,
        help="Contract code"
    )
    
    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate report"
    )
    report_parser.add_argument(
        "--findings",
        type=eval,
        default=[],
        help="Findings list"
    )
    report_parser.add_argument(
        "-f", "--format",
        type=str,
        default="markdown",
        help="Report format"
    )
    report_parser.add_argument(
        "-n", "--name",
        type=str,
        help="Contract name"
    )
    
    # REPL command
    repl_parser = subparsers.add_parser(
        "repl",
        help="Start interactive REPL"
    )
    repl_parser.add_argument(
        "-p", "--provider",
        type=str,
        default="gemini",
        help="AI provider"
    )
    repl_parser.add_argument(
        "-s", "--script",
        type=str,
        help="Script file to run"
    )
    
    # Session commands
    session_parser = subparsers.add_parser(
        "session",
        help="Session management"
    )
    session_sub = session_parser.add_subparsers(dest="session_action")
    session_sub.add_parser("list", help="List sessions")
    
    # Provider commands
    provider_parser = subparsers.add_parser(
        "provider",
        help="Provider management"
    )
    provider_sub = provider_parser.add_subparsers(dest="provider_action")
    provider_sub.add_parser("list", help="List providers")
    
    # Version command
    version_parser = subparsers.add_parser(
        "version",
        help="Show version"
    )
    
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