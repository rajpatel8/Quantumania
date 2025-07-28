from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Core requirements that are mandatory
core_requirements = [
    "pathlib2>=2.3.7",
    "typing-extensions>=4.0.0",
    "lxml>=4.9.0",
]

# Enhanced requirements that are optional
enhanced_requirements = [
    "pyyaml>=6.0",
    "jinja2>=3.1.0", 
    "click>=8.1.0",
]

# Development requirements
dev_requirements = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
]

setup(
    name="quantum-crypto-scanner",
    version="0.2.0",  # Step 2 version
    author="Your Name",
    author_email="your.email@example.com",
    description="Enhanced quantum crypto vulnerability scanner with CBOM generation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/quantum-crypto-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",  # Upgraded from Alpha
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=core_requirements,
    extras_require={
        "enhanced": enhanced_requirements,
        "dev": dev_requirements,
        "all": enhanced_requirements + dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "quantum-crypto-scan=quantum_crypto_scanner.main:main",
        ],
    },
    keywords="cryptography quantum security vulnerability scanner cbom post-quantum",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/quantum-crypto-scanner/issues",
        "Source": "https://github.com/yourusername/quantum-crypto-scanner",
        "Documentation": "https://github.com/yourusername/quantum-crypto-scanner/wiki",
    },
)