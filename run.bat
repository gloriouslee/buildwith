@echo off
cd /d "%~dp0"
if not exist .venv (
  py -m venv .venv
  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
if not exist data\signatures\categories.json .venv\Scripts\python.exe update_signatures.py
.venv\Scripts\python.exe app.py
