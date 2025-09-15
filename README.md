# 🔐 pyauthx

> **Modern, strongly-typed, production-grade authentication toolkit for Python.**

[![PyPI version](https://img.shields.io/pypi/v/pyauthx?color=blue&style=for-the-badge)](https://pypi.org/project/pyauthx/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/hexguard/pyauthx/ci.yml?style=for-the-badge)](https://github.com/hexguard/pyauthx/actions)

---

## ✨ Features

- **🔑 Strongly-typed JWT issuance & verification** — access/refresh tokens with Pydantic validation.
- **🔄 Refresh tokens with mTLS binding** — secure rotation with optional certificate thumbprint binding.
- **🔒 Key Management** — automatic JWK rotation, JWKS endpoint support, strong algorithms (HS256/RS256/ES256).
- **📊 Built-in Metrics (soon)** — Prometheus histograms/counters for latency, token issuance, verification failures.
- **🛠 Developer Tools (soon)** — optional `[devtools]` extras with local token inspector & pretty logging.
- **⚡ Async-ready** — works in FastAPI, Starlette, Flask, or any modern Python web stack.

---

## 🚀 Quick Start

```bash
pip install pyauthx
```
