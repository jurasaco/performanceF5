#!/bin/bash
git pull
pip install -r requirements.txt
pyinstaller --add-data 'modules/__report__.html:modules/' --onefile performanceF5.py
cp -f dist/performanceF5 /usr/bin/