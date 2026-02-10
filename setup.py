"""Configuration d'installation du package."""

from setuptools import setup, find_packages

setup(
    name='phishing-analyzer',
    version='1.0.0',
    description='Outil de detection heuristique de phishing par email',
    author='Security Team',
    python_requires='>=3.7',
    packages=find_packages(),
    install_requires=[
        'beautifulsoup4>=4.12.0',
    ],
    entry_points={
        'console_scripts': [
            'phishing-analyzer=main:main',
        ],
    },
)
