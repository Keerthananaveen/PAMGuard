import argparse
from app.services.audit_service import list_audit_logs
from app.database import initialize_database, seed_database
from app.services.rbac_service import (
    list_users,
    has_role
)
from app.services.account_service import (
    create_privileged_account,
    list_privileged_accounts
)
from app.services.policy_service import (
    create_policy,
    list_policies
)
from app.services.access_service import (
    request_access,
    list_access_requests,
    approve_access,
    checkout_password
)
from app.services.session_service import (
    list_sessions,
    checkin_session,
    expire_sessions
)
from app.services.password_service import (
    rotate_password
)
from app.services.siem_service import search_events, export_events
from app.services.response_service import respond
from app.services.monitor_service import watch


def create_account():
    operator = input("Operator username: ").strip()
    username = input("Privileged account username: ").strip()
    hostname = input("Hostname: ").strip()
    platform = input("Platform: ").strip()
    safe = input("Safe: ").strip()

    success, message = create_privileged_account(
        operator,
        username,
        hostname,
        platform,
        safe
    )

    print(message)


def show_accounts():
    accounts = list_privileged_accounts()

    print("\nPAMGuard Privileged Accounts")
    print("-" * 100)

    if not accounts:
        print("No privileged accounts found.")
        return

    for account in accounts:
        print(
            f"{account['username']:<20} "
            f"{account['hostname']:<20} "
            f"{account['platform']:<12} "
            f"{account['safe']:<20} "
            f"{account['status']:<10}"
        )


def create_access_policy():
    operator = input("Operator username: ").strip()
    name = input("Policy name: ").strip()
    safe = input("Safe: ").strip()
    max_duration = int(
        input("Maximum duration in minutes: ").strip()
    )
    approval_required = int(
        input("Approval required? (1=yes, 0=no): ").strip()
    )
    rotation_interval = int(
        input("Rotation interval in hours: ").strip()
    )

    success, message = create_policy(
        operator,
        name,
        safe,
        max_duration,
        approval_required,
        rotation_interval
    )

    print(message)


def show_policies():
    policies = list_policies()

    print("\nPAMGuard Access Policies")
    print("-" * 100)

    if not policies:
        print("No policies found.")
        return

    for policy in policies:
        print(
            f"{policy['name']:<30} "
            f"{policy['safe']:<20} "
            f"Max: {policy['max_duration_minutes']} min   "
            f"Approval: {policy['approval_required']}   "
            f"Rotation: {policy['rotation_interval_hours']} hrs"
        )


def create_access_request():
    username = input("Requester username: ").strip()
    account_username = input(
        "Privileged account username: "
    ).strip()
    hostname = input("Hostname: ").strip()
    duration = int(
        input("Duration in minutes: ").strip()
    )
    reason = input("Reason: ").strip()

    success, message = request_access(
        username,
        account_username,
        hostname,
        duration,
        reason
    )

    print(message)


def show_access_requests():
    requests = list_access_requests()

    print("\nPAMGuard Access Requests")
    print("-" * 120)

    if not requests:
        print("No access requests found.")
        return

    for request in requests:
        print(
            f"{request['request_id']:<15} "
            f"{request['requester']:<10} "
            f"{request['account_username']:<15} "
            f"{request['hostname']:<20} "
            f"{request['status']:<12} "
            f"{request['requested_duration_minutes']} min   "
            f"{request['reason']}"
        )


def approve_request():
    request_id = input("Request ID: ").strip()
    approver = input("Approver username: ").strip()

    success, message = approve_access(
        approver,
        request_id
    )

    print(message)


def checkout_request():
    username = input("Username: ").strip()
    request_id = input("Request ID: ").strip()
    source_ip = input("Source IP: ").strip()

    success, message = checkout_password(
        username,
        request_id,
        source_ip
    )

    print(message)


def show_sessions():
    sessions = list_sessions()

    print("\nPAMGuard Sessions")
    print("-" * 120)

    if not sessions:
        print("No sessions found.")
        return

    for session in sessions:
        print(
            f"{session['session_id']:<15} "
            f"{session['username']:<10} "
            f"{session['account_username']:<15} "
            f"{session['hostname']:<20} "
            f"{session['status']:<10} "
            f"{session['start_time']}"
        )


def checkin_existing_session():
    username = input("Username: ").strip()
    session_id = input("Session ID: ").strip()

    success, message = checkin_session(
        username,
        session_id
    )

    print(message)


def expire_existing_sessions():
    count = expire_sessions()

    print(f"\nExpired sessions: {count}")


def rotate_existing_password():
    operator = input("Operator username: ").strip()
    account_username = input(
        "Privileged account username: "
    ).strip()
    hostname = input("Hostname: ").strip()

    success, message = rotate_password(
        operator,
        account_username,
        hostname
    )

    print(message)

def show_audit_logs():
    logs = list_audit_logs()

    print("\nPAMGuard Audit Log")
    print("-" * 130)

    if not logs:
        print("No audit events found.")
        return

    for log in logs:
        print(
            f"{log['timestamp']:<30} "
            f"{log['event_type']:<25} "
            f"{str(log['username'] or 'SYSTEM'):<12} "
            f"{str(log['account_username'] or '-'):<15} "
            f"{log['result']:<10} "
            f"{log['details']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="PAMGuard - Privileged Access Management Lab"
    )

    parser.add_argument(
        "--init-db",
        action="store_true"
    )

    parser.add_argument(
        "--seed",
        action="store_true"
    )

    parser.add_argument(
        "--users",
        action="store_true"
    )

    parser.add_argument(
        "--check-role",
        nargs=2,
        metavar=("USERNAME", "ROLE")
    )

    parser.add_argument(
        "--create-account",
        action="store_true"
    )

    parser.add_argument(
        "--accounts",
        action="store_true"
    )

    parser.add_argument(
        "--create-policy",
        action="store_true"
    )

    parser.add_argument(
        "--policies",
        action="store_true"
    )

    parser.add_argument(
        "--request-access",
        action="store_true"
    )

    parser.add_argument(
        "--requests",
        action="store_true"
    )

    parser.add_argument(
        "--approve",
        action="store_true"
    )

    parser.add_argument(
        "--checkout",
        action="store_true"
    )

    parser.add_argument(
        "--sessions",
        action="store_true"
    )

    parser.add_argument(
        "--checkin",
        action="store_true"
    )

    parser.add_argument(
        "--expire-sessions",
        action="store_true"
    )

    parser.add_argument(
        "--rotate",
        action="store_true"
    )

    parser.add_argument(
        "--audit",
        action="store_true"
    )

    parser.add_argument("--siem-search", metavar="TEXT")
    parser.add_argument("--siem-severity", metavar="LEVEL")
    parser.add_argument("--siem-export", action="store_true")
    parser.add_argument("--watch-logs", action="store_true")
    parser.add_argument("--watch-once", action="store_true")
    parser.add_argument("--response", choices=("disable-account", "expire-session", "investigate"))
    parser.add_argument("--incident-id")
    parser.add_argument("--account-username")
    parser.add_argument("--hostname")
    parser.add_argument("--session-id")

    args = parser.parse_args()

    if args.init_db:
        initialize_database()

    elif args.seed:
        seed_database()

    elif args.users:
        users = list_users()

        print("\nPAMGuard Users")
        print("-" * 70)

        for user in users:
            print(
                f"{user['username']:<12} "
                f"{user['email']:<30} "
                f"{user['status']:<10} "
                f"{user['roles'] or '-'}"
            )

    elif args.check_role:
        username, role = args.check_role

        if has_role(username, role):
            print(
                f"ACCESS GRANTED: {username} has role {role}"
            )
        else:
            print(
                f"ACCESS DENIED: {username} does not have role {role}"
            )

    elif args.create_account:
        create_account()

    elif args.accounts:
        show_accounts()

    elif args.create_policy:
        create_access_policy()

    elif args.policies:
        show_policies()

    elif args.request_access:
        create_access_request()

    elif args.requests:
        show_access_requests()

    elif args.approve:
        approve_request()

    elif args.checkout:
        checkout_request()

    elif args.sessions:
        show_sessions()

    elif args.checkin:
        checkin_existing_session()

    elif args.expire_sessions:
        expire_existing_sessions()

    elif args.rotate:
        rotate_existing_password()

    elif args.audit:
        show_audit_logs()

    elif args.siem_search is not None or args.siem_severity:
        rows = search_events(args.siem_search, args.siem_severity)
        for row in rows:
            print(f"{row.get('incident_id')} {row.get('severity')} {row.get('incident_type')} {row.get('username')}@{row.get('hostname')} {row.get('source_ip')}")
        print(f"Events: {len(rows)}")

    elif args.siem_export:
        print(f"Local SIEM-style export: {export_events()}")

    elif args.watch_logs or args.watch_once:
        print("Watching the configured local Windows CSV log (Ctrl+C to stop)." if args.watch_logs else "Checking the configured local Windows CSV log once.")
        watch(once=args.watch_once)

    elif args.response:
        if not args.incident_id:
            parser.error("--incident-id is required with --response")
        ok, message = respond(args.response, args.incident_id, args.account_username, args.hostname, args.session_id)
        print(message)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
