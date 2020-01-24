import os
import re
import setuptools

envstring = lambda var: os.environ.get(var) or ""

here = os.path.abspath(os.path.dirname(__file__))
about = {}

with open(os.path.join(here, 'li_privacy', '__version__.py'), 'r') as f:
    exec(f.read(), about)

with open(os.path.join(here, "README.md"), "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    dependencies = fh.read().strip().split("\n")

setuptools.setup(
    name=about['__title__'],
    version=about['__version__'],
    author=about['__author__'],
    author_email=about['__author_email__'],
    entry_points={"console_scripts": ["li-privacy=li_privacy.cli:main"]},
    description=about['__description__'],
    install_requires=dependencies,
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
    url=about['__url__'],
    long_description=long_description,
    long_description_content_type="text/markdown",
    license=about['__license__'],
    packages=[about['__title__']],
    classifiers=[
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
