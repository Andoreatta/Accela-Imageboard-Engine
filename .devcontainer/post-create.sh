#!/usr/bin/env bash
set -euo pipefail

service postgresql start
su postgres -c "psql -c \"ALTER USER postgres PASSWORD 'accela_dev';\""

mix local.hex --force
mix local.rebar --force
mix setup
