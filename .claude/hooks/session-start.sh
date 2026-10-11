#!/bin/bash
# Installs graphify (pip package + /graphify skill); it is not a marketplace plugin.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

if ! command -v graphify >/dev/null 2>&1; then
  if command -v uv >/dev/null 2>&1; then
    uv tool install --quiet graphifyy
  else
    python3 -m pip install --user --quiet graphifyy
  fi
fi

if [ ! -f "$HOME/.claude/skills/graphify/SKILL.md" ]; then
  graphify install >/dev/null
fi
