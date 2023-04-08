import os, sys

from setuptools import setup, Extension
from distutils.command import build_ext

try:
    import pybind11
    pybind11_include_path = pybind11.get_include()
except ImportError:
    pybind11_include_path = ""

ext_name = "cryptopp"

py_ver = sys.version_info[:2]

include_dirs = [
    "./include",
]
if pybind11_include_path:
    include_dirs.append(pybind11_include_path)
libraries = [
    "cryptopp",
]

library_dirs = [
    "./lib/",
]

sources = []

source_path = "./src/"
for dirname, dirs, filenames in os.walk(source_path):
    for filename in sorted(filenames):
        if not filename.lower().endswith(".cpp"):
            continue
        sources.append(os.path.join(dirname, filename))
    break

extras = [
    "-std=c++17",
]

ext = Extension(name="{0}.__{0}".format(ext_name),
                include_dirs=include_dirs,
                libraries=libraries,
                library_dirs=library_dirs,
                sources=sources,
                extra_compile_args=extras)


install_requires = []
requirements_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "requirements.txt")
if os.path.exists(requirements_path):
    with open(requirements_path) as fp:
        install_requires = fp.read().splitlines()

setup(
    name=ext_name,
    packages=[ext_name],
    license="BSL-1.0",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Boost Software License 1.0 (BSL-1.0)",
        "Programming Language :: Python :: 3.8",
    ],
    ext_modules=[ext],
    install_requires=install_requires,
)
