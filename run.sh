#!/usr/bin/env sh
set -e
uv sync --dev
uv run radar init-db
uv run radar serve
