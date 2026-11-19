"""RAVEN V7 Shared Runtime.

One runtime for all V7 subsystems — Chat, Browser, Terminal, Agent, Scripts,
Research, Learning. No isolated per-feature loops.
"""
from .runtime import RavenRuntime, RuntimeState
from .tasks import Task, TaskStatus, TaskRegistry
from .events import EventBus, RuntimeEvent
from .tools import ToolDescriptor as ToolDefinition, ToolRegistry, ToolDispatcher, ToolResult, ToolStatus
from .capabilities import CapabilityGate, CapabilityDecision
from .execution import ExecutionRecord
from .workspace import WorkspaceContext
from .conversation import ConversationContext, Message
from .model import ModelService, ModelProvider
from .checkpoint import CheckpointEngine
from .plugins import PluginManifest, PluginRegistry
from .errors import RuntimeError as RavenRuntimeError, ErrorCategory

__all__ = [
    "RavenRuntime", "RuntimeState",
    "Task", "TaskStatus", "TaskRegistry",
    "EventBus", "RuntimeEvent",
    "ToolDefinition", "ToolRegistry", "ToolDispatcher", "ToolResult", "ToolStatus",
    "CapabilityGate", "CapabilityDecision",
    "ExecutionRecord",
    "WorkspaceContext",
    "ConversationContext", "Message",
    "ModelService", "ModelProvider",
    "CheckpointEngine",
    "PluginManifest", "PluginRegistry",
    "RavenRuntimeError", "ErrorCategory",
]
