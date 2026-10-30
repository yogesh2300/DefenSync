"""Regular expressions for secure.log and audit.log parsing."""

from __future__ import annotations

import re

# Syslog header shared by /var/log/secure lines.
SECURE_HEADER = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:]+?)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s*(?P<message>.*)$"
)

# journalctl --output=short-iso
ISO_SECURE_HEADER = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:]+?)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s*(?P<message>.*)$"
)

SECURE_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
SECURE_INVALID_USER_AUTH = re.compile(
    r"input_userauth_request:\s+invalid user (?P<user>\S+)",
    re.IGNORECASE,
)
SECURE_FAILED_INVALID_USER = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"for invalid user (?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
SECURE_FAILED_LOGIN = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"for (?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
SECURE_SUCCESSFUL_LOGIN = re.compile(
    r"Accepted\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"for (?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
SECURE_SUDO_COMMAND = re.compile(
    r"^(?:sudo:\s*)?(?P<user>\S+)\s*:\s*(?P<details>.*COMMAND=(?P<cmd>.+))$",
    re.IGNORECASE,
)
SECURE_SUDO_SESSION = re.compile(
    r"pam_unix\(sudo(?::session)?:\).*session opened for user (?P<target>\S+)",
    re.IGNORECASE,
)
# util-linux su: "(to root) ysalve on pts/0", or "FAILED SU (to root) ysalve on pts/0".
SECURE_SU_SWITCH = re.compile(
    r"^(?P<failed>FAILED SU )?\(to (?P<target>[^)\s]+)\) (?P<user>\S+) on (?P<tty>\S+)\s*$"
)
# "pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=ysalve"
SECURE_PAM_AUTH_FAILURE = re.compile(
    r"^pam_unix\((?P<service>[\w.-]+):auth\): authentication failure;(?P<fields>.*)$"
)
# "pam_unix(sshd:session): session opened for user ysalve(uid=1000) by ysalve(uid=0)"
SECURE_PAM_SESSION = re.compile(
    r"^pam_unix\((?P<service>[\w.-]+):session\): session (?P<action>opened|closed) "
    r"for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?"
)
PAM_FIELD = re.compile(r"(\w+)=(\S*)")

AUDIT_KV = re.compile(r'(\w+)=("(?:\\.|[^"\\])*"|[^\s]+)')
AUDIT_TIMESTAMP = re.compile(r"msg=audit\(([\d.]+):\d+\)")

AUDIT_SYSCALL_NAMES = {
    "1": "write",
    "2": "open",
    "83": "mkdir",
    "84": "rmdir",
    "87": "unlink",
    "257": "openat",
    "258": "mkdirat",
    "263": "unlinkat",
    "90": "chmod",
    "91": "chown",
    "268": "fchmodat",
    "269": "fchownat",
    "59": "execve",
}

MKDIR_SYSCALLS = frozenset({"mkdir", "mkdirat"})
FILE_CREATE_SYSCALLS = frozenset({"creat", "open", "openat"})
FILE_DELETE_SYSCALLS = frozenset({"unlink", "unlinkat", "rmdir"})
PERM_SYSCALLS = frozenset(
    {"chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown"}
)
