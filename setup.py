"""
Setup script for flask_google_groups_auth module
"""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="flask-google-groups-auth",
    version="0.1.0",
    author="Jeff Davis",
    author_email="jeff@roitraining.com",
    description="Flask module for Google authentication and Google Group membership checking",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jwdavis/flask-google-groups-auth",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: Flask",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    keywords="flask google authentication oauth google-groups cloud-run",
    project_urls={
        "Bug Reports": "https://github.com/jwdavis/flask-google-groups-auth/issues",
        "Source": "https://github.com/jwdavis/flask-google-groups-auth",
    },
)
