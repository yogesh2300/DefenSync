"""Read-only SSH diagnostic for registered Linux servers.

Usage (from project root):
    .venv\\Scripts\\python.exe scripts\\diagnose_ssh.py            # all servers
    .venv\\Scripts\\python.exe scripts\\diagnose_ssh.py <server_id>

Reports NETWORK_ERROR / SSH_TIMEOUT / AUTHENTICATION_FAILED / CREDENTIAL_ERROR /
COMMAND_EXECUTION_FAILED / SUCCESS per server. Does not modify the database and
never prints stored credentials.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.database import server_crud  # noqa: E402
from backend.database.connection import get_session  # noqa: E402
from backend.services.ssh_service import SSHService  # noqa: E402


def main(argv: list[str]) -> int:
    session = get_session()
    try:
        servers = server_crud.list_servers(session)
        if len(argv) > 1:
            servers = [server for server in servers if server.id == argv[1]]
        if not servers:
            print("No matching servers.")
            return 1
        exit_code = 0
        for server in servers:
            report = SSHService.diagnose_server(server, timeout=5.0)
            print(f"== {server.server_name} ({server.host}:{server.port}, user={server.username})")
            print(f"   result : {report['result']}")
            print(f"   message: {report['message']}")
            print("   steps  :", json.dumps(report["steps"], indent=2, default=str).replace("\n", "\n   "))
            if not report["success"]:
                exit_code = 2
        return exit_code
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
