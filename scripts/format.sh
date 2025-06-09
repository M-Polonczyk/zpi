#!/bin/sh -e
set -x

ruff check backend/app backend/scripts --fix
ruff format backend/app backend/scripts
