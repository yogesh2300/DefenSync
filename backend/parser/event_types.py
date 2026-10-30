"""Supported security event classifications for the log parser."""

from __future__ import annotations

from enum import StrEnum


class EventType(StrEnum):
    """Event types detected from secure.log and audit.log entries."""

    FAILED_LOGIN = "Failed Login"
    SUCCESSFUL_LOGIN = "Successful Login"
    INVALID_USER = "Invalid User"
    SUDO_COMMAND = "Sudo Command"
    USER_CREATION = "User Creation"
    USER_DELETION = "User Deletion"
    DIRECTORY_CREATION = "Directory Creation"
    FILE_CREATION = "File Creation"
    FILE_DELETION = "File Deletion"
    PERMISSION_CHANGE = "Permission Change"
    COMMAND_EXECUTION = "Command Execution"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    FAILED_PRIVILEGE_ESCALATION = "Failed Privilege Escalation"
    SESSION_OPENED = "Session Opened"
    SESSION_CLOSED = "Session Closed"
