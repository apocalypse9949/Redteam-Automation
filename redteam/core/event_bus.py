"""
Event Bus - Pub/sub event system for decoupled module communication.
Enables real-time dashboard updates and inter-module coordination.
"""

import asyncio
import logging
from typing import Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict


logger = logging.getLogger("redteam.event_bus")


@dataclass
class Event:
    """Represents an event in the system."""
    type: str
    data: dict = field(default_factory=dict)
    source: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "data": self.data,
            "source": self.source,
            "timestamp": self.timestamp,
        }


class EventBus:
    """
    Asynchronous event bus for inter-module communication.
    
    Supported events:
    - phase_change: Attack phase transition
    - scan_started / scan_complete: Port/service scanning
    - vuln_found: Vulnerability discovered
    - exploit_attempt / exploit_success / exploit_failed: Exploitation
    - shell_obtained: Shell access gained
    - priv_escalated: Privilege escalation successful
    - lateral_move: Lateral movement to new host
    - persistence_planted: Persistence mechanism established
    - credentials_found: Credentials harvested
    - step_added: New attack step recorded
    - log: General log message
    """

    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._async_subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._history: list[Event] = []
        self._max_history = 10000

    def subscribe(self, event_type: str, callback: Callable) -> None:
        """Register a synchronous callback for an event type."""
        self._subscribers[event_type].append(callback)
        logger.debug(f"Subscriber registered for '{event_type}'")

    def subscribe_async(self, event_type: str, callback: Callable) -> None:
        """Register an async callback for an event type."""
        self._async_subscribers[event_type].append(callback)
        logger.debug(f"Async subscriber registered for '{event_type}'")

    def subscribe_all(self, callback: Callable) -> None:
        """Register a callback for all events."""
        self.subscribe("*", callback)

    def subscribe_all_async(self, callback: Callable) -> None:
        """Register an async callback for all events."""
        self.subscribe_async("*", callback)

    async def emit(self, event_type: str, data: dict = None, source: str = "") -> None:
        """Emit an event to all subscribers."""
        event = Event(type=event_type, data=data or {}, source=source)
        self._history.append(event)

        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        # Call synchronous subscribers
        for callback in self._subscribers.get(event_type, []):
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in event handler for '{event_type}': {e}")

        for callback in self._subscribers.get("*", []):
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in wildcard handler: {e}")

        # Call async subscribers
        for callback in self._async_subscribers.get(event_type, []):
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Error in async handler for '{event_type}': {e}")

        for callback in self._async_subscribers.get("*", []):
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Error in async wildcard handler: {e}")

    def emit_sync(self, event_type: str, data: dict = None, source: str = "") -> None:
        """Emit an event synchronously (for non-async contexts)."""
        event = Event(type=event_type, data=data or {}, source=source)
        self._history.append(event)

        for callback in self._subscribers.get(event_type, []):
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in sync handler for '{event_type}': {e}")

        for callback in self._subscribers.get("*", []):
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in sync wildcard handler: {e}")

    def get_history(self, event_type: str = None, limit: int = 100) -> list[Event]:
        """Get event history, optionally filtered by type."""
        if event_type:
            events = [e for e in self._history if e.type == event_type]
        else:
            events = self._history
        return events[-limit:]

    def clear_history(self) -> None:
        """Clear all event history."""
        self._history.clear()

    def unsubscribe_all(self) -> None:
        """Remove all subscribers."""
        self._subscribers.clear()
        self._async_subscribers.clear()


# Global event bus instance
event_bus = EventBus()
