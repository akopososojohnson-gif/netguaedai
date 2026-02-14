#!/bin/bash
# Fix settings file

SETTINGS_FILE="/opt/netguard/web/netguard_web/settings.py"

echo "Fixing $SETTINGS_FILE..."

# Replace timescale engine with regular postgresql
sed -i 's/timescale.db.backends.postgresql/django.db.backends.postgresql/g' "$SETTINGS_FILE"

# Remove channels from INSTALLED_APPS if present
sed -i "/'channels'/d" "$SETTINGS_FILE"
sed -i '/"channels"/d' "$SETTINGS_FILE"

echo "Done!"
echo ""
echo "Current ENGINE setting:"
grep "ENGINE" "$SETTINGS_FILE" | head -1
