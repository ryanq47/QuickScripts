@echo off

REM Check if 'venv' virtual environment folder exists
IF NOT EXIST "venv" (
    python -m venv venv
    echo Virtual environment created.
)

REM Activate virtual environment
CALL venv\Scripts\activate

REM Install dependencies
pip install flask markdown

REM Start the server
python server.py

REM Deactivate the virtual environment
CALL venv\Scripts\deactivate
