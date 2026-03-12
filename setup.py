#!/usr/bin/env python
"""Setup script for Heimdall NIDS."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="heimdall-ids",
    version="0.1.0",
    description="Network Intrusion Detection System (NIDS) and packet analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="timnik.com",
    url="https://github.com/yourusername/heimdall",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "heimdall=heimdall.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    keywords="ids nids intrusion detection network sniffer packet analysis",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/heimdall/issues",
        "Documentation": "https://github.com/yourusername/heimdall/blob/main/README.md",
        "Source Code": "https://github.com/yourusername/heimdall",
    },
)
