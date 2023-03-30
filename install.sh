#!/bin/bash
echo "Updating from git"
git pull
echo "Installing requirements..."
pip install pyinstaller
pip install -r requirements.txt
echo "Generating pyinstaller executable package..."
pyinstaller --add-data 'modules/__report__.html:modules/' --onefile performanceF5.py
echo "Copying performanceF5 executable to /usr/bin/..."
cp -f dist/performanceF5 /usr/bin/
echo "Done!"