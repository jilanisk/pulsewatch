#!/bin/sh
set -eu
# Seed a brand-new Docker volume with the V1 JSON export. Existing volumes
# containing their own sites.json are left untouched.
if [ ! -f /app/data/sites.json ] && [ -f /app/seed/sites.json ]; then
  cp /app/seed/sites.json /app/data/sites.json
fi
exec "$@"
