import pathlib
from setuptools import setup

try:
    import re2 as re
except ImportError:
    import re

packages = ["sharkiq"]

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# Pull the version from __init__.py so we don't need to maintain it in multiple places
init_txt = (HERE / packages[0] / "__init__.py").read_text("utf-8")
try:
    version = re.findall(r"^__version__ = ['\"]([^'\"]+)['\"]\r?$", init_txt, re.M)[0]
except IndexError:
    raise RuntimeError('Unable to determine version.')


setup(
    name="sharkiq",
    version=version,
    description="Python API for Shark IQ robots",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/sharkiqlibs/sharkiq-ng",
    author="Jeff Rescignano",
    author_email="jeff@jeffresc.dev",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    packages=packages,
    include_package_data=False,
    install_requires=list(val.strip() for val in open("requirements.txt")),
)
