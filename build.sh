#!/usr/bin/env sh
pip uninstall haprestio -y
python3 setup.py bdist_wheel
pip install dist/*
[ -f docker/*whl ] && rm docker/*whl
mv dist/* docker