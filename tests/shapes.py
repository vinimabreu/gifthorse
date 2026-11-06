"""The fourteen acceptance shapes from the spec, built once and shared.

S1 to S6 are synthetic reconstructions of delivery shapes seen in the wild and
must come back BLOCK. B1 to B8 are ordinary projects and document packages and
must come back NO FINDINGS. The acceptance test and the naive-filter baseline
test both use exactly these bytes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from . import builders as b


@dataclass(frozen=True)
class Shape:
    key: str
    target: str
    summary: str
    data: bytes

    @property
    def malicious(self) -> bool:
        return self.key.startswith("S")


def s1() -> Shape:
    data = b.make_zip(
        {
            "screenshot1.png": b.PNG,
            "screenshot2.png": b.PNG,
            "Project Requirements and Budget.vbs": b.vbs_dropper().encode(),
        }
    )
    return Shape("S1", "brief.zip", "zip of screenshots plus a .vbs dropper", data)


def s2() -> Shape:
    data = b.make_rar5(
        {
            "screenshot1.png": b.PNG,
            "Project Requirements and Budget.vbs": b"rem placeholder for a windows script",
        }
    )
    return Shape("S2", "brief.rar", "the same in a RAR5", data)


def s3() -> Shape:
    data = b.make_zip(
        {
            "package.json": b'{"name": "demo"}',
            "postcss.config.js": b.postcss_offscreen().encode(),
            "app/page.tsx": b"export default function Page() { return null }",
        }
    )
    return Shape("S3", "vite-app.zip", "postcss.config.js with an off-screen payload", data)


def s4() -> Shape:
    data = b.make_zip(
        {
            "README.md": b"# Setup\n\nRun `git checkout whitepaper` to begin.\n",
            "docs/spec.md": b"spec text\n",
            ".git/config": b"[core]\n",
            ".git/hooks/post-checkout": b.git_hook_background().encode(),
            ".git/hooks/pre-commit": b.git_hook_background().encode(),
        }
    )
    return Shape("S4", "rwa-pack.zip", "git repository with active hooks", data)


def s5() -> Shape:
    data = b.make_zip(
        {
            "README.md": b.readme_curl_install().encode(),
            "install.sh": b.installer_with_persistence().encode(),
        }
    )
    return Shape("S5", "helper-tool.zip", "install.sh that pipes a download to a shell", data)


def s6() -> Shape:
    data = b.make_zip(
        {
            "package.json": b"{}",
            ".vscode/tasks.json": b.vscode_task_folder_open().encode(),
            "src/index.js": b"console.log(1)\n",
        }
    )
    return Shape("S6", "project.zip", ".vscode/tasks.json that runs on folder open", data)


def b1() -> Shape:
    config = (
        b"const config = { plugins: { '@tailwindcss/postcss': {} } };\nexport default config;\n"
    )
    data = b.make_zip(
        {
            "package.json": b'{"scripts": {"dev": "next dev", "build": "next build", '
            b'"start": "next start", "lint": "next lint"}}',
            "next.config.mjs": b"const nextConfig = {};\nexport default nextConfig;\n",
            "postcss.config.mjs": config,
            "eslint.config.mjs": b"export default [];\n",
            "tsconfig.json": b"{}",
            "app/page.tsx": b"export default function Page() { return null }\n",
        }
    )
    return Shape("B1", "next-app.zip", "create-next-app style project", data)


def b2() -> Shape:
    data = b.make_zip(
        {
            "package.json": b'{"scripts": {"dev": "vite", "build": "vite build"}}',
            "vite.config.ts": b"import react from '@vitejs/plugin-react';\n"
            b"export default { plugins: [react()] };\n",
            "src/main.tsx": b"import App from './App'\n",
        }
    )
    return Shape("B2", "vite-react.zip", "Vite and React template", data)


def b3() -> Shape:
    data = b.make_zip(
        {
            "package.json": b'{"scripts": {"prepare": "husky"}}',
            ".husky/pre-commit": b"npx lint-staged\n",
        }
    )
    return Shape("B3", "with-husky.zip", "husky prepare script and pre-commit", data)


def b4() -> Shape:
    data = b.make_zip(
        {
            "pyproject.toml": b"[build-system]\nrequires = ['setuptools']\n"
            b"build-backend = 'setuptools.build_meta'\n",
            "setup.py": b"from setuptools import setup\n\nsetup()\n",
            "tests/conftest.py": b"import pytest\n\n\n@pytest.fixture\ndef sample():\n"
            b"    return 1\n",
        }
    )
    return Shape("B4", "pkg.zip", "plain setuptools package", data)


def b5() -> Shape:
    data = b.make_zip(
        {
            "README.md": b"# Project\n",
            ".git/config": b"[core]\n\trepositoryformatversion = 0\n"
            b'[remote "origin"]\n\turl = https://example.invalid/x/y.git\n'
            b'[branch "main"]\n\tremote = origin\n',
            ".git/hooks/pre-commit.sample": b"#!/bin/sh\nexit 0\n",
            ".git/hooks/post-checkout.sample": b"#!/bin/sh\nexit 0\n",
        }
    )
    return Shape("B5", "repo.zip", "git repository with sample hooks only", data)


def b6() -> Shape:
    data = b.make_zip(
        {
            "screenshot1.png": b.PNG,
            "screenshot2.png": b.PNG,
            "brief.pdf": b.PDF,
            "__MACOSX/._screenshot1.png": b"\x00\x00",
            ".DS_Store": b"\x00\x00",
        }
    )
    return Shape("B6", "docs.zip", "images, a PDF and macOS metadata", data)


def b7() -> Shape:
    data = b.make_zip(
        {
            "package.json": b"{}",
            ".vscode/tasks.json": b.vscode_task_build().encode(),
        }
    )
    return Shape("B7", "proj.zip", "editor build task without runOn", data)


def b8() -> Shape:
    data = b.make_zip(
        {
            "build.gradle": b"plugins { id 'java' }\n",
            "settings.gradle": b"rootProject.name = 'demo'\n",
            "gradlew": b'#!/bin/sh\nexec gradle "$@"\n',
            "gradlew.bat": b"@echo off\ngradle %*\n",
            # a real jar is a valid zip; a wrapper jar carries a manifest
            "gradle/wrapper/gradle-wrapper.jar": b.make_zip(
                {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"}
            ),
            "src/main/java/Main.java": b"public class Main {}\n",
        }
    )
    return Shape("B8", "java-app.zip", "Gradle project with the wrapper jar", data)


BUILDERS: tuple[Callable[[], Shape], ...] = (
    s1,
    s2,
    s3,
    s4,
    s5,
    s6,
    b1,
    b2,
    b3,
    b4,
    b5,
    b6,
    b7,
    b8,
)


def all_shapes() -> list[Shape]:
    return [build() for build in BUILDERS]


def shape(key: str) -> Shape:
    for build in BUILDERS:
        if build.__name__ == key.lower():
            return build()
    raise KeyError(key)
