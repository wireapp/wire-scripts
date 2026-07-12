Provisioning IdP for teams in Mobtown deployment

# Prerequisites

## Wire server

- Multi-ingress SSO configuration
- Teams credentials

## Dependencies

- jq
- curl
- domains
- idp metadata files

# How to run the scripts

## idp-provisioner.sh

This script provides two subcommands:

- get: List the IdPs configured for a team
- set: Add an IdP to a team.

This script require NGINZ_HOST env. In a multi-ingress deployment, you can use any available domain as the value of NGINZ_HOST to get or configure IdP for a team

### get

The subcommand accepts team credentials as parameters and send api request to NGINZ_HOST.

### set

The set subcommand accepts the team credentials and two additional parameters:

- domain: the domain associated with the IdP
- The IdP metadata file

Example:

```
./idp-provisioner get team-a team-a-password
./idp-provisioner set team-a team-a-password blueberry.domain.com blueberry.domain.com.xml

```

## Authentication

Before making any api call, this script authenticates using provided team credentials. The successful authentication response is stored in a temporary file. The script reuses the access_token for subsequent requests or automatically obtains a new one when the existing token expires.

## Tmp folder

By default, this script stores temporary files in the system's `/tmp`. You can override this location by setting the TMP_DIR env.

## domain-wrapper.sh

This script wraps idp-provisioner.sh and allows you to config multiple IdPs for a single team.

It requires the team credentials and the directory containing the IdP metadata files.

The script assumes that each metadata file is named after its corresponding domain. For instance:

- Domain: blueberry.domain.com
- Idp metadata file: blueberry.domain.com.xml


Example:

```
./domain-wrapper.sh set team-a team-a-password ./idps

```

## team-wrapper.sh

This script wraps domain-wrapper.sh and iterates over a list of team to provision all available IdPs for each team.

This script requires:

- A teams.json file containing the team credentials
- The directory containing the IdP metadata files.

Team credentials are stored in a JSON file to avoid issues with special characters in team passwords.

Example:

```
./team-wrapper.sh set ./teams/teams.json ./idps

```