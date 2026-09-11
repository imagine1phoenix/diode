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


# Modules that enable outbound network connections or inbound servers — FORBIDDEN in ingest
FORBIDDEN_MODULES = {
    "socket",
    "http.client",
    "http.server",
    "socketserver",
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
    "websockets",
}

FORBIDDEN_CALLS = {
    "socket.connect",
    "socket.sendto",
    "socket.send",
    "urlopen",
    "requests.get",
    "requests.post",
    "create_connection",
    "create_server",
    "start_server",
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
        """
        Use AST visitor to inspect every Call node in src/ingest/ for outbound network calls
        or write operations. Replaces fragile string matching with structural AST analysis.
        """
        violations = []
        forbidden_methods = {"connect", "send", "sendto", "sendall", "post", "put", "patch", "delete"}

        for py_file in INGEST_DIR.glob("*.py"):
            source = py_file.read_text()
            tree = ast.parse(source)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check method calls like socket.connect, requests.post, etc.
                    if isinstance(node.func, ast.Attribute):
                        method_name = node.func.attr
                        if method_name in forbidden_methods:
                            violations.append(
                                f"{py_file.name}:{node.lineno} calls forbidden method '{method_name}()'"
                            )
                    # Check bare function calls like urlopen()
                    elif isinstance(node.func, ast.Name):
                        if node.func.id in {"urlopen", "socket"}:
                            violations.append(
                                f"{py_file.name}:{node.lineno} calls forbidden function '{node.func.id}()'"
                            )
                        # Check file write modes
                        elif node.func.id == "open":
                            for arg in node.args[1:]:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    if any(m in arg.value for m in ("w", "a", "+")):
                                        violations.append(
                                            f"{py_file.name}:{node.lineno} calls open() with write mode '{arg.value}'"
                                        )

        if violations:
            self.fail(
                "OUTBOUND CALL / WRITE DETECTED IN INGEST (rules.md R1.1):\n"
                + "\n".join(f"  - {v}" for v in violations)
            )

    def test_runtime_namespace_has_no_sockets(self):
        """Dynamically inspect imported ingest modules to confirm zero socket/network objects."""
        for mod_name in ["src.ingest.reader", "src.ingest.flow_assembler"]:
            mod = importlib.import_module(mod_name)
            for attr_name in dir(mod):
                if attr_name.startswith("__"):
                    continue
                attr = getattr(mod, attr_name)
                # Check that no socket type, client, or HTTP session exists in module namespace
                type_str = str(type(attr)).lower()
                for forbidden in ["socket.socket", "httpx.client", "requests.session", "urllib.request"]:
                    if forbidden in type_str:
                        self.fail(f"Ingest module {mod_name} exposes forbidden runtime object: {attr_name}={attr}")

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
