"""RAVEN V7 Plugin Foundation.

Defines plugin contracts and lifecycle (§160-163).
Plugins CANNOT self-grant authority (§162).
Plugin failure isolation: a broken plugin must not crash the runtime (§163).
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class PluginState(str, Enum):
    DISCOVERED   = "DISCOVERED"
    VALIDATED    = "VALIDATED"
    LOADED       = "LOADED"
    ACTIVE       = "ACTIVE"
    DISABLED     = "DISABLED"
    FAILED       = "FAILED"
    INCOMPATIBLE = "INCOMPATIBLE"


PLUGIN_API_VERSION = "7.0"


@dataclass
class PluginManifest:
    """Machine-readable plugin descriptor (§160).

    Declared capabilities are NOT grants — runtime/policy determines availability (§162).
    """
    plugin_id:          str
    name:               str
    version:            str
    api_version:        str
    entrypoint:         str = ""
    description:        str = ""
    capabilities:       List[str] = field(default_factory=list)  # declared, not granted
    tools:              List[str] = field(default_factory=list)
    event_subscriptions: List[str] = field(default_factory=list)
    metadata:           Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "api_version": self.api_version,
            "entrypoint": self.entrypoint,
            "description": self.description,
            "capabilities": self.capabilities,
            "tools": self.tools,
            "event_subscriptions": self.event_subscriptions,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PluginManifest":
        return cls(
            plugin_id=d["plugin_id"],
            name=d.get("name", ""),
            version=d.get("version", "0.0.0"),
            api_version=d.get("api_version", ""),
            entrypoint=d.get("entrypoint", ""),
            description=d.get("description", ""),
            capabilities=d.get("capabilities", []),
            tools=d.get("tools", []),
            event_subscriptions=d.get("event_subscriptions", []),
            metadata=d.get("metadata", {}),
        )


@dataclass
class LoadedPlugin:
    manifest:     PluginManifest
    state:        PluginState = PluginState.DISCOVERED
    loaded_at:    Optional[int] = None
    error:        Optional[str] = None
    # Granted capabilities are a SUBSET of declared, determined by policy
    granted_capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            **self.manifest.to_dict(),
            "state": self.state.value,
            "loaded_at": self.loaded_at,
            "error": self.error,
            "granted_capabilities": self.granted_capabilities,
        }


class PluginRegistry:
    """Manages plugin lifecycle with failure isolation (§160-163).

    Responsibilities:
    - Validate manifest (api_version compatibility, required fields, unique IDs)
    - Track lifecycle state
    - Prevent self-granted authority escalation
    - Isolate failures so one broken plugin does not crash the runtime
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._plugins: Dict[str, LoadedPlugin] = {}

    def register(self, manifest: PluginManifest) -> LoadedPlugin:
        """Validate and register a plugin manifest.

        Returns the plugin in VALIDATED or INCOMPATIBLE/FAILED state.
        Registration NEVER grants capabilities — that requires policy approval.
        """
        # Duplicate ID check (§222)
        with self._lock:
            if manifest.plugin_id in self._plugins:
                existing = self._plugins[manifest.plugin_id]
                existing.state = PluginState.FAILED
                existing.error = f"Duplicate plugin_id: '{manifest.plugin_id}'"
                return existing

        plugin = LoadedPlugin(manifest=manifest)

        # API version compatibility (§161)
        try:
            major_expected = int(PLUGIN_API_VERSION.split(".")[0])
            major_provided = int(manifest.api_version.split(".")[0])
            if major_provided != major_expected:
                plugin.state = PluginState.INCOMPATIBLE
                plugin.error = (
                    f"Plugin API version {manifest.api_version} incompatible "
                    f"with runtime {PLUGIN_API_VERSION}"
                )
                with self._lock:
                    self._plugins[manifest.plugin_id] = plugin
                return plugin
        except (ValueError, IndexError):
            plugin.state = PluginState.INCOMPATIBLE
            plugin.error = f"Invalid api_version: '{manifest.api_version}'"
            with self._lock:
                self._plugins[manifest.plugin_id] = plugin
            return plugin

        # Required fields
        if not manifest.plugin_id.strip():
            plugin.state = PluginState.FAILED
            plugin.error = "plugin_id must not be empty"
            with self._lock:
                self._plugins[manifest.plugin_id] = plugin
            return plugin

        plugin.state = PluginState.VALIDATED
        with self._lock:
            self._plugins[manifest.plugin_id] = plugin
        return plugin

    def activate(self, plugin_id: str, granted_capabilities: List[str]) -> bool:
        """Activate a validated plugin with policy-approved capabilities.

        granted_capabilities MUST be determined by policy, never by plugin declaration alone.
        """
        with self._lock:
            plugin = self._plugins.get(plugin_id)
            if plugin is None or plugin.state != PluginState.VALIDATED:
                return False
            # Escalation check: granted must be subset of declared (§162)
            undeclared = set(granted_capabilities) - set(plugin.manifest.capabilities)
            if undeclared:
                plugin.state = PluginState.FAILED
                plugin.error = f"Undeclared capability escalation attempt: {undeclared}"
                return False
            plugin.granted_capabilities = list(granted_capabilities)
            plugin.state = PluginState.ACTIVE
            plugin.loaded_at = int(time.time() * 1000)
            return True

    def deactivate(self, plugin_id: str) -> bool:
        with self._lock:
            plugin = self._plugins.get(plugin_id)
            if plugin and plugin.state == PluginState.ACTIVE:
                plugin.state = PluginState.DISABLED
                return True
            return False

    def mark_failed(self, plugin_id: str, error: str) -> None:
        """Record plugin failure without crashing the runtime (§163)."""
        with self._lock:
            plugin = self._plugins.get(plugin_id)
            if plugin:
                plugin.state = PluginState.FAILED
                plugin.error = error

    def get(self, plugin_id: str) -> Optional[LoadedPlugin]:
        with self._lock:
            return self._plugins.get(plugin_id)

    def list_active(self) -> List[LoadedPlugin]:
        with self._lock:
            return [p for p in self._plugins.values() if p.state == PluginState.ACTIVE]

    def list_all(self) -> List[LoadedPlugin]:
        with self._lock:
            return list(self._plugins.values())

    def count(self, state: PluginState = None) -> int:
        with self._lock:
            if state is None:
                return len(self._plugins)
            return sum(1 for p in self._plugins.values() if p.state == state)
