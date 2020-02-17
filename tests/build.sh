#!/usr/bin/env sh
rm -f .ash_history
rm -f .python_history
docker build -t testing .
