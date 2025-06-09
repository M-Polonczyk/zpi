#!/bin/bash

set -e

export PYTHONPATH=/app/app:$PYTHONPATH

python app/backend_pre_start.py

python app/initial_data.py

exec "$@"