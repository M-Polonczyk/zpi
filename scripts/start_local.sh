#!/bin/bash

set -e

echo "Starting compose stack..."
docker compose up --build -d

echo "Starting frontend..."
cd frontend
npm install
npm run dev

echo "Local environment started successfully."
