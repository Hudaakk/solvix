#!/bin/bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Navigate to the directory containing manage.py
cd tcms

# Apply migrations
python manage.py collectstatic --no-input
python manage.py makemigrations
python manage.py migrate