#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Install Python dependencies
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Run migrations
python manage.py migrate

# You can add other build steps here if needed, such as:
# - Compiling assets
# - Running tests
# - Generating documentation

echo "Build completed successfully!"