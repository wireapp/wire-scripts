#!/usr/bin/env python3

# Verified against backend 5.5
# to be executed inside the wire-utility pod
# After dumping brig.user, galley.clients, and gundeck.user_push, we use galley.clients as the source of all known clients per user, and brig.user only to map user IDs to emails.
# gundeck.user_push.client is matched against galley.clients.clients: matching push clients are classified by ARN as iOS (APNS) or Android (GCM/FCM).
# Any client present in galley.clients.clients but missing from gundeck.user_push.client is counted as a Webapp/Desktop client.
# We count total unique users, total unique clients, per-client-type counts, per-user client-type usage, and list Webapp/Desktop clients with their user ID and email.
# Any push client present in gundeck.user_push but missing from galley.clients is reported separately as an inconsistency.

import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./cql_export")

push_csv = data_dir / "user_push.csv"
galley_csv = data_dir / "galley_clients.csv"
brig_csv = data_dir / "brig_user.csv"

push_by_client = {}
ios_clients = set()
android_clients = set()
ios_users = set()
android_users = set()

with push_csv.open(newline="") as f:
    for row in csv.DictReader(f):
        client = row["client"].strip()
        arn = row["arn"].strip()
        user = row["usr"].strip()

        push_by_client[client] = {"user": user, "arn": arn}

        if ":endpoint/APNS/" in arn or ":endpoint/APNS_SANDBOX/" in arn:
            ios_clients.add(client)
            ios_users.add(user)
        elif ":endpoint/GCM/" in arn or ":endpoint/FCM/" in arn:
            android_clients.add(client)
            android_users.add(user)

galley_clients_by_user = defaultdict(set)
galley_all_clients = set()
galley_users = set()

with galley_csv.open(newline="") as f:
    for row in csv.DictReader(f):
        user = row["user"].strip()
        clients_raw = row["clients"].strip()

        clients = re.findall(r"[0-9a-fA-F]+", clients_raw)
        if clients:
            galley_users.add(user)

        for client in clients:
            galley_clients_by_user[user].add(client)
            galley_all_clients.add(client)

emails = {}

with brig_csv.open(newline="") as f:
    for row in csv.DictReader(f):
        emails[row["id"].strip()] = row["email"].strip()

push_clients = set(push_by_client)

push_clients_missing_in_galley = sorted(push_clients - galley_all_clients)
webapp_clients = sorted(galley_all_clients - push_clients)

missing_in_galley_by_user = defaultdict(list)
for client in push_clients_missing_in_galley:
    user = push_by_client[client]["user"]
    missing_in_galley_by_user[user].append(client)

webapp_clients_by_user = defaultdict(list)
for user, clients in galley_clients_by_user.items():
    for client in sorted(clients - push_clients):
        webapp_clients_by_user[user].append(client)

all_known_clients = galley_all_clients | push_clients
all_known_users = galley_users | {v["user"] for v in push_by_client.values()}

print("=== Total known clients and users ===")
print(f"Unique users:  {len(all_known_users)}")
print(f"Total clients: {len(all_known_clients)}")
print()

print("=== Client type summary ===")
print(f"iOS clients:     {len(ios_clients)}")
print(f"Android clients: {len(android_clients)}")
print(f"Webapp/Desktop clients:  {len(webapp_clients)}")
print(f"Unknown push clients not in galley.clients: {len(push_clients_missing_in_galley)}")
print()

print("=== Client Type usage accros the users ===")
print(f"Users using iOS:     {len(ios_users)}")
print(f"Users using Android: {len(android_users)}")
print(f"Users using Webapp/Desktop:  {len(webapp_clients_by_user)}")
print(f"Total users using Mobile clients(iOS/Android): {len(ios_users | android_users)}")
print()

print("=== Push clients (iOS/Android) if not present in galley.clients (all clients) ===")
print(f"Count: {len(push_clients_missing_in_galley)}")
for user, clients in sorted(missing_in_galley_by_user.items()):
    print(f"user={user} email={emails.get(user, 'UNKNOWN')} clients={clients}")
print()

print("=== Webapp/Desktop clients: galley.clients not present in gundeck.user_push ===")
print(f"Count: {len(webapp_clients)}")
for user, clients in sorted(webapp_clients_by_user.items()):
    print(f"user={user} email={emails.get(user, 'UNKNOWN')} clients={clients}")

