import os
import shutil
from pathlib import Path

import setuptools
from setuptools.command import build_ext


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


# [ref](https://github.com/google/trimmed_match/blob/master/setup.py)
class BazelExtension(setuptools.Extension):
    """A C/C++ extension that is defined as a Bazel BUILD target."""

    def __init__(self, bazel_workspace, bazel_target, ext_name):
        self._bazel_target = bazel_target
        self._bazel_workspace = bazel_workspace
        setuptools.Extension.__init__(self, ext_name, sources=[])


class BuildBazelExtension(build_ext.build_ext):
    """A command that runs Bazel to build a C/C++ extension."""

    def run(self):
        for ext in self.extensions:
            self.bazel_build(ext)
        build_ext.build_ext.run(self)

    def bazel_build(self, ext):
        Path(self.build_temp).mkdir(parents=True, exist_ok=True)
        bazel_argv = [
            "bazel",
            "build",
            f"@{ext._bazel_workspace}//:{ext._bazel_target}",
            "--symlink_prefix=" + os.path.join(os.path.abspath(self.build_temp), "bazel-"),
            "--compilation_mode=" + ("dbg" if self.debug else "opt"),
        ]

        self.spawn(bazel_argv)

        ext_bazel_bin_path = os.path.join(
            self.build_temp,
            "bazel-bin/external",
            ext._bazel_workspace,
            ext._bazel_target,
        )
        ext_dest_path = self.get_ext_fullpath(ext.name)
        Path(ext_dest_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ext_bazel_bin_path, ext_dest_path)


setuptools.setup(
    name="sdc-sdk",
    version="0.0.3",
    author="secretflow",
    author_email="secretflow-contact@service.alipay.com",
    description="Secure Data Capsule SDK for python",
    long_description_content_type="text/markdown",
    long_description="Secure Data Capsule SDK for python",
    license="Apache 2.0",
    url="https://github.com/secretflow/secure-data-capsule-sdk",
    packages=setuptools.find_namespace_packages(exclude=("tests", "tests.*")),
    install_requires=read("requirements.txt"),
    ext_modules=[
        BazelExtension(
            "jinzhao_attest", "libverification.so", "sdc/lib/libverification"
        ),
        BazelExtension("jinzhao_attest", "libgeneration.so", "sdc/lib/libgeneration"),
    ],
    cmdclass=dict(build_ext=BuildBazelExtension),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Business License",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
)
