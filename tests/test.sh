#!/usr/bin/env sh
#pip install -r requirements.txt
pytest -x --tb=long --verbose test_combin.py $@
