"""
Test: Ingest Isolation — Verify the ingest module has no outbound network capability.

rules.md R1: The ingest layer MUST NOT contain any outbound network calls.
rules.md R1.5: This must be architecturally demonstrable and verifiable by code review.

This test inspects the source code of the ingest modules to ensure they
don't import or use any networking modules that could enable outbound calls.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import unittest
from pathlib import Path


# Modules that enable outbound network connections — FORBIDDEN in ingest
FORBIDDEN_MODULES = {
    "socket",
    "http.client",
    "urllib",
    "urllib.request",
    "urllib3",
    "requests",
    "httpx",
    "aiohttp",
    "grpc",
    "paramiko",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
}

FORBIDDEN_CALLS = {
    "socket.connect",
    "socket.sendto",
    "socket.send",
    "urlopen",
    "requests.get",
    "requests.post",
}

INGEST_DIR = Path(__file__).parent.parent / "src" / "ingest"


class TestIngestIsolation(unittest.TestCase):
    """Verify that the ingest module cannot make outbound network calls."""

    def test_no_forbidden_imports_in_source(self):
        """Scan all .py files in src/ingest/ for forbidden import statements."""
        violations = []

        for py_file in INGEST_DIR.glob("*.py"):
            source = py_file.read_text()
            try:
                tree = ast.parse(source)
            except SyntaxError:
                self.fail(f"Syntax error in {py_file}")

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_root = alias.name.split(".")[0]
                        if alias.name in FORBIDDEN_MODULES or module_root in FORBIDDEN_MODULES:
                            violations.append(
                                f"{py_file.name}:{node.lineno} imports '{alias.name}'"
                            )

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module_root = node.module.split(".")[0]
                        if node.module in FORBIDDEN_MODULES or module_root in FORBIDDEN_MODULES:
                            violations.append(
                                f"{py_file.name}:{node.lineno} imports from '{node.module}'"
                            )

        if violations:
            self.fail(
                "INGEST ISOLATION VIOLATION (rules.md R1):\n"
                + "\n".join(f"  - {v}" for v in violations)
            )

    def test_no_outbound_socket_usage(self):
        """Scan source code for socket.connect and similar calls."""
        violations = []

        for py_file in INGEST_DIR.glob("*.py"):
            source = py_file.read_text()
            for forbidden in FORBIDDEN_CALLS:
                if forbidden in source:
                    violations.append(
                        f"{py_file.name} contains '{forbidden}'"
                    )

        if violations:
            self.fail(
                "OUTBOUND CALL DETECTED IN INGEST (rules.md R1.1):\n"
                + "\n".join(f"  - {v}" for v in violations)
            )

    def test_ingest_modules_exist(self):
        """Verify ingest package structure is correct."""
        self.assertTrue(
            (INGEST_DIR / "__init__.py").exists(),
            "src/ingest/__init__.py missing",
        )
        self.assertTrue(
            (INGEST_DIR / "reader.py").exists(),
            "src/ingest/reader.py missing",
        )
        self.assertTrue(
            (INGEST_DIR / "flow_assembler.py").exists(),
            "src/ingest/flow_assembler.py missing",
        )


if __name__ == "__main__":
    unittest.main()
