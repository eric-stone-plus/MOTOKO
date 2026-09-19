"""Hermes registration only; the engine owns all scanning and graph state."""
from .tools import register_tools


def register(ctx):
    register_tools(ctx)
