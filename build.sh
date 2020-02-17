#!/usr/bin/env sh
pip uninstall haprestio -y
python3 setup.py sdist bdist_wheel
pip install dist/*
[ -f docker/*whl ] && rm docker/*whl
cp dist/*whl docker