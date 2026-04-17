#!/usr/bin/env python3
"""
Solidify Main Entry Point
Web3 Smart Contract Security Auditor
"""

import sys

if sys.platform == "winay":
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer)

import asyncio
import argparse
import logging
import os
import json

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def cmd_hunt(args: argparse.Namespace) -> None:
    """Run vulnerability hunt"""
    if args.ask:
        asyncio.run(cmd_ask(args))
        return

    if args.url or args.file or args.address:
        asyncio.run(cmd_hunt_advanced(args))
    else:
        print("SoliGuard - Web3 Security Auditor")
        print(
            "Usage: python main.py hunt --file <contract.sol> -m minimaxai/minimax-m2.5"
        )


async def cmd_ask(args: argparse.Namespace) -> None:
    """Answer security questions"""
    from providers.provider_factory import create_provider

    provider = create_provider(args.provider or "nvidia")
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

    provider = create_provider(provider_name)

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
                chunk = chunk.decode('utf-8', errors='replace')
            
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


def main():
    parser = argparse.ArgumentParser(
        prog="Solidify", description="Web3 Smart Contract Security Auditor"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Hunt command
    hunt = subparsers.add_parser("hunt", help="Hunt for vulnerabilities")
    hunt.add_argument("--file", "-f", help="Contract file")
    hunt.add_argument("--url", help="Contract URL")
    hunt.add_argument("--address", help="Contract address")
    hunt.add_argument("--model", "-m", default="minimaxai/minimax-m2.5", help="Model")
    hunt.add_argument("--provider", "-p", default="nvidia", help="Provider")
    hunt.add_argument("--task", help="Task")
    hunt.add_argument("--ask", help="Ask question")
    hunt.add_argument("--type", help="Vuln type")
    hunt.add_argument("--poc", action="store_true", help="Generate PoC")

    args = parser.parse_args()

    if not args.command:
        cmd_hunt(
            argparse.Namespace(
                file=None,
                url=None,
                address=None,
                model="minimaxai/minimax-m2.5",
                provider="nvidia",
                task=None,
                ask=None,
                type=None,
                poc=False,
            )
        )
    elif args.command == "hunt":
        cmd_hunt(args)


if __name__ == "__main__":
    main()
