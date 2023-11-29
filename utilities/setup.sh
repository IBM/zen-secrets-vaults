#!/bin/sh

python3 -m pip install --user virtualenv
rm -rf venv
python3 -m venv env
source env/bin/activate
