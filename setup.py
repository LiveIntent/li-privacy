import os
import re
import setuptools

envstring = lambda var: os.environ.get(var) or ""

try:
    with open("README.md", "r") as fh:
        long_description = fh.read()
except:
    long_description = ""

if os.path.isfile("variables"):
    try:
        with open("variables", "r") as fh:
            variables = fh.read().strip().split("\n")
        for v in variables:
            key, value = v.split("=")
            os.environ[key] = re.sub("['\"]", "", value)
    except:
        pass

if os.path.isfile("requirements.txt"):
    with open("requirements.txt", "r") as fh:
        dependencies = fh.read().strip().split("\n")
else:
    dependencies = []

import li_privacy

setuptools.setup(
    name=envstring("NAME"),
    version=li_privacy.__version__,
    author=envstring("AUTHOR"),
    author_email=envstring("AUTHOR_EMAIL"),
    entry_points={"console_scripts": ["li-privacy=li_privacy.cli:main"]},
    description=envstring("DESCRIPTION"),
    install_requires=dependencies,
    url=envstring("URL"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=[envstring("NAME")],
    classifiers=[
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
