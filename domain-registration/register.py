#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import base64
import json
import os

deafult_file_marker = -321
default_host = "https://staging-nginz-https.zinfra.io"
default_dns_verification_token = "<<PREVIOUSLY RECEIVED TOKEN>>"

def tee(file, *message):
    print(*message)
    if file != None:
        file.write(" ".join(message) + "\n")
        file.flush()

def die(*message):
    print("ERROR!")
    print("\n".join(message))
    exit(1)

def wait():
    print("")
    print("Press ENTER to continue")
    input()

def ask_domain():
    print("")
    print("######### WIRE DOMAIN REGISTRATION #########")
    print("")
    print("This script will register a domain on WIRE for redirection to a self-hosted instance")
    print("Please make sure the Wire customer support has pre-authorized this domain")
    print("")
    print("Please enter the domain")
    return input("")

def get_verification_challenge(cloud_host, domain):
    print("Requesting verification challenge...")

    response = requests.post(f"{cloud_host}/v8/domain-verification/{domain}/challenges")
    response.status_code == 200 or die("Failed to register domain\nResponse:\n", response.text)

    body = response.json()
    dns_verification_token = body["dns_verification_token"]
    challenge_id = body["id"]
    challenge_token = body["token"]

    print("")
    print(f"\tChallenge ID: {challenge_id}")
    print(f"\tChallenge Token: {challenge_token}")
    print(f"\tDNS Verification Token: {dns_verification_token}")
    print("")
    return (dns_verification_token, challenge_id, challenge_token)

def print_instructions(domain, dns_verification_token):
    print("")
    print(f"Please add the following DNS TXT record to your domain `{domain}`")
    print("")
    print(f"\t{dns_verification_token}")
    print(f"\tIN TXT wire-domain.{domain}")
    print("")
    print("Press ENTER when you have created DNS the record")
    input("")

def complete_challenge(cloud_host, domain, challenge_id, token):
    print("Completing challenge...")

    response = requests.post(f"{cloud_host}/v8/domain-verification/{domain}/challenges/{challenge_id}",
                             json={"challenge_token": token})
    if response.status_code != 200:
        try:
            body = response.json()
            label = body["label"]
        except:
            die("Failed to complete challenge\nResponse:\n", response.text)

        if label == "operation-forbidden-for-domain-registration-state":
            die("The domain is not in the correct state to complete the challenge. " + \
                "Has it been pre-authorized by Wire customer support?")
        elif label == "domain-verification-failed":
            print("The verification failed. Please check the DNS record and try again.")
            print("It's possible that the DNS record is still propagating. In this case, please wait a few seconds and try again.")
            print("Press ENTER to try to verify again now, or type any letter (e.g. 'q') to abort")
            choice = input("")
            if choice.lower() == "" or choice.lower() == "y":
                return complete_challenge(cloud_host, domain, challenge_id, token)
            else:
                print("Aborting...")
                exit(1)
        else:
            die("Failed to complete challenge\nResponse:\n", response.text)
        
    response.status_code == 200 or die("Failed to complete challenge\nResponse:\n", response.text)

    body = response.json()
    token = body["domain_ownership_token"]
    print(f"SUCCESS!")
    print(f"Domain ownership token:")
    print(f"\t{token}")
    print(f"Save this value somewhere safe. You will need it for any following change to the domain configuration")
    wait()
    return token

def ask_backend_config_url(default):
    print("")
    print("Please enter the redirect URL for your backend")
    if(default):
        print(f"Default: {default}. Press ENTER to use the default, or type a new URL")
    answer = input("")
    if(answer.strip() == ""):
        return default
    return answer.strip()

def put_configuration(cloud_host, domain, domain_ownership_token, backend_url):
    print("Setting configuration...")
    print(f"Domain: {domain}")
    print(f"Domain ownership token: {domain_ownership_token}")
    print(f"Backend URL: {backend_url}")
    print("")

    response = requests.post(f"{cloud_host}/v8/domain-verification/{domain}/backend",
                             json={"domain_redirect": "backend",
                                   "backend_url": backend_url},
                             headers={"Authorization": f"Bearer {domain_ownership_token}"})
    response.status_code == 200 or die("Failed to register domain\nResponse:\n", response.text)

    print("Domain registered successfully!")

def verify_domain(cloud_host, email):
    response = requests.post(f"{cloud_host}/v8/get-domain-registration",
                             json={"email": email})
    if response.status_code == 503:
        die("The domain registration service is not available")
    response.status_code == 200 or die("Unexpected response", response.text)
    print(response.json())

if __name__ == "__main__":


    parser = argparse.ArgumentParser(description="Register a domain for WIRE")
    parser.add_argument("--cloud_host", help="Cloud host to use", default=default_host)
    parser.add_argument("--domain", help="Domain to register")
    parser.add_argument("--challenge_id", help="Challenge ID")
    parser.add_argument("--challenge_token", help="Token to complete the challenge")
    parser.add_argument("--domain_ownership_token", help="Domain ownership token")
    parser.add_argument("--backend_config_url", help="Backend configuration URL")
    parser.add_argument("--verify_email", help="Email to verify the domain registration. If you pass this value, " \
    "the script will not register a domain, but will only verify the domain registration for that email", default=None)
    parser.add_argument("--file", help="File where to read and save the progress of the process, " \
    "inclding tokens. If you don't want this information to be saved on disk, pass the string `null`. Defalts to " \
    "`<domain>.json`", default=deafult_file_marker)
    parser.add_argument("--dns_verification_token", 
                        help="DNS verification token previously generated (optional, just needed for instructions)", 
                        default=default_dns_verification_token) 
    args = parser.parse_args()

    
    cloud_host = args.cloud_host
    print(f"Using cloud host {cloud_host}...")

    if args.verify_email:
        verify_domain(cloud_host, args.verify_email)
        exit(0)

    domain = args.domain or ask_domain()
    metadata = {
        "domain": domain 
    }
    print(f"Using domain {domain}...")
    
    output_file = None
    if args.file == deafult_file_marker:
        output_file = f"{domain}.json"
    elif not args.file in ["null", "None", "`null`", "none", "nul"]:
        output_file = args.file

    if output_file != None and os.path.exists(output_file):
        print(f"Do you want to load previous progress from {output_file}?")
        print("[Y]es / [N]o (default Yes):")
        choice = input("")
        if choice.lower() == "y" or choice == "yes" or choice == "":
            with open(output_file) as fin:
                metadata = json.loads(fin.read())
                if "domain" in metadata and metadata["domain"] != domain:
                    die("The domain in the progress file does not match the domain passed as argument")

                print(f"Loaded progress from {output_file}:")
                print("\n".join([f"\t{x}" for x in json.dumps(metadata, indent=4).split("\n")]))

    if output_file != None:
        print(f"Saving progress and tokens to {output_file}")


    def save():
        if output_file != None:
            with open(output_file, "w") as out:
                out.write(json.dumps(metadata, indent=4))
    save()

    challenge_id = args.challenge_id or metadata.get("challenge_id")
    challenge_token = args.challenge_token or metadata.get("challenge_token")
    domain_ownership_token = args.domain_ownership_token or metadata.get("domain_ownership_token")
    dns_verification_token = args.dns_verification_token if args.dns_verification_token != default_dns_verification_token else metadata.get("dns_verification_token")
    backend_url = args.backend_config_url or metadata.get("backend_url")

    if challenge_id != None \
        and challenge_token != None \
        and (challenge_id == None or challenge_token == None):
        die("Please provide both challenge ID and challenge token")
    if not domain_ownership_token:
        if not challenge_id:
            dns_verification_token, challenge_id, challenge_token = get_verification_challenge(cloud_host, domain)
        metadata["challenge_id"] = challenge_id
        metadata["challenge_token"] = challenge_token
        metadata["dns_verification_token"] = dns_verification_token
        save()
        print_instructions(domain, dns_verification_token)
        domain_ownership_token = complete_challenge(cloud_host, domain, challenge_id, challenge_token)
        metadata["domain_ownership_token"] = domain_ownership_token
        save()
    else:
        domain_ownership_token = domain_ownership_token
        metadata["domain_ownership_token"] = domain_ownership_token
        save()

    backend_url = args.backend_config_url or ask_backend_config_url(metadata.get("backend_url"))
    metadata["backend_url"] = backend_url
    save()
    put_configuration(cloud_host, domain, domain_ownership_token, backend_url)