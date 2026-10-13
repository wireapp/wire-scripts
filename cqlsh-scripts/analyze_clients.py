#!/usr/bin/env python3

# Verified against backend 5.5
# to be executed inside the wire-utility pod
# After dumping brig.user, brig.clients, and gundeck.user_push, we use brig.clients as the source of all known clients per user, and brig.user only to map user IDs to emails.
# gundeck.user_push is matched against brig.clients: matching push clients are classified by ARN as iOS (APNS) or Android (GCM/FCM).
# Any client present in brig.clients but missing from gundeck.user_push is counted as a non-FCM/APNS device.
# These non-FCM/APNS devices are then categorized based on model type: "firefox" or "chrome" => Webapp, "Wire Desktop" => Desktop, rest => Other.
# We count total unique users, total clients, per-client-type counts, per-user client-type usage, and list Webapp/Desktop clients with their user ID and email.
# Any push client present in gundeck.user_push but missing from brig.clients is reported separately as an inconsistency.

import csv
import sys
from collections import defaultdict
from pathlib import Path

data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./cql_export")

push_csv = data_dir / "user_push.csv"
brig_csv = data_dir / "brig_user.csv"
brig_clients_csv = data_dir / "brig_clients.csv"

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

# Read clients from brig_clients.csv (source of truth)
brig_clients_by_user = defaultdict(set)
brig_all_clients = set()
brig_users = set()
client_to_user = {}
model_by_client = {}
label_by_client = {}
tstamp_by_client = {}

with brig_clients_csv.open(newline="") as f:
    for row in csv.DictReader(f):
        user = row.get("user", "").strip()
        client = row.get("client", "").strip()
        label = row.get("label", "").strip()
        model = row.get("model", "").strip()
        tstamp = row.get("tstamp", "").strip()

        if not client:
            continue

        brig_users.add(user)
        brig_clients_by_user[user].add(client)
        brig_all_clients.add(client)
        client_to_user[client] = user
        model_by_client[client] = model
        label_by_client[client] = label
        tstamp_by_client[client] = tstamp

# Read emails mapping from brig_user.csv
emails = {}
with brig_csv.open(newline="") as f:
    for row in csv.DictReader(f):
        emails[row["id"].strip()] = row["email"].strip()

push_clients = set(push_by_client.keys())

# Push clients present in user_push but missing from brig.clients -> inconsistency
push_clients_missing_in_brig = sorted(push_clients - brig_all_clients)

# Clients present in brig.clients but missing from user_push -> non-FCM/APNS devices (no push)
non_fcm_apns_clients = sorted(brig_all_clients - push_clients)

# Categorize non-FCM/APNS clients by model: webapp (firefox|chrome), desktop (wire), other
non_fcm_by_user = defaultdict(list)
webapp_clients_by_user = defaultdict(list)
desktop_clients_by_user = defaultdict(list)
other_non_fcm_by_user = defaultdict(list)

webapp_clients = []
desktop_clients = []
other_non_fcm = []

for client in non_fcm_apns_clients:
    user = client_to_user.get(client, "UNKNOWN")
    model = model_by_client.get(client, "")
    m = model.lower()

    non_fcm_by_user[user].append(client)

    if "firefox" in m or "chrome" in m:
        webapp_clients_by_user[user].append(client)
        webapp_clients.append(client)
    elif "wire" in m:
        # treat Wire-* models (Wire Desktop / Wire Linux) as Desktop
        desktop_clients_by_user[user].append(client)
        desktop_clients.append(client)
    else:
        other_non_fcm_by_user[user].append(client)
        other_non_fcm.append(client)

all_known_clients = brig_all_clients | push_clients
all_known_users = brig_users | {v["user"] for v in push_by_client.values()}

print("=== Total known clients and users ===")
print(f"Unique users:  {len(all_known_users)}")
print(f"Total clients: {len(all_known_clients)}")
print()

print("=== Client type summary ===")
print(f"iOS clients:     {len(ios_clients)}")
print(f"Android clients: {len(android_clients)}")
print(f"non-FCM/APNS devices (in brig.clients but not in user_push): {len(non_fcm_apns_clients)}")
print(f"  - Webapp:   {len(webapp_clients)}")
print(f"  - Desktop:  {len(desktop_clients)}")
print(f"  - Other:    {len(other_non_fcm)}")
print(f"Push clients missing in brig.clients (in user_push only): {len(push_clients_missing_in_brig)}")
print()

print("=== Client Type usage across the users ===")
print(f"Users using iOS:     {len(ios_users)}")
print(f"Users using Android: {len(android_users)}")
print(f"Users with Webapp clients:  {len(webapp_clients_by_user)}")
print(f"Users with Desktop clients: {len(desktop_clients_by_user)}")
print(f"Users with unidentified clients: {len(other_non_fcm)}")
print()


print(f"Webapp Clients details: {len(webapp_clients)}")
for user in sorted(webapp_clients_by_user.keys()):
    print(f"user={user} email={emails.get(user, 'UNKNOWN')} webapp_clients={webapp_clients_by_user[user]}")
print()
print(f"Desktop Clients details: {len(desktop_clients)}")
for user in sorted(desktop_clients_by_user.keys()):
    print(f"user={user} email={emails.get(user, 'UNKNOWN')} desktop_clients={desktop_clients_by_user[user]}")
print()

# Print non-fcm/apns-non-webapp-non-desktop users with details: email,label,model,clientid,tstamp
print("=== Clients which are not active (no active push token) Android or iOS type and neither identified as Desktop/Webapp ===")
for user in sorted(other_non_fcm_by_user.keys()):
    for client in other_non_fcm_by_user[user]:
        print(
            f"user={user} "
            f"email={emails.get(user, 'UNKNOWN')} "
            f"client={client} "
            f"label={label_by_client.get(client, 'UNKNOWN')} "
            f"model={model_by_client.get(client, 'UNKNOWN')} "
            f"tstamp={tstamp_by_client.get(client, 'UNKNOWN')}"
        )
