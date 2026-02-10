from setuptools import setup, find_packages

setup(
    name='phishing-email-analyzer',
    version='1.0.0',
    description='Outil de détection heuristique de phishing par analyse de fichiers .eml',
    author='Security Team',
    python_requires='>=3.7',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'phishing-analyzer=main:main',
        ],
    },
)
