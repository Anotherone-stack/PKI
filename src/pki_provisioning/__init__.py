[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "pki-provisioning"
version = "0.1.0"
description = "Starter project for PKI and provisioning workflows"
readme = "README.md"
requires-python = ">=3.10"
authors = [{ name = "Anotherone-stack" }]
license = { text = "Apache-2.0" }
dependencies = [
    "cryptography>=42.0.0",
    "fastapi>=0.111.0",
    "uvicorn>=0.30.0",
]

[project.scripts]
pki-provisioning = "pki_provisioning.cli:main"

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]
