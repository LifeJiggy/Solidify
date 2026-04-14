"""
SoliGuard - Web3 Smart Contract Security Auditor
Python Package Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("backend/requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="soliguard",
    version="1.0.0",
    author="Team SoliGuard",
    author_email="Bloomtonjovish@gmail.com",
    description="AI-powered smart contract security auditor for Web3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LifeJiggy/Solidify",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "soliguard=solidify.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "solidify": ["config/*.json"],
    },
)