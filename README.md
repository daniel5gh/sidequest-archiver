# Sidequest APK Archiver

## Overview
Automates monitoring and archiving of APK files from Sidequest for any app ID. Ensures you always have access to previous versions, regardless of publisher restrictions.

## Motivation
Publishers love to yank old releases and force updates—because, of course, they know best. But I'll decide what versions I run, thank you very much. This tool lessens that pain and takes over control.

## Quickstart
```bash
# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate  # On Windows
source .venv/bin/activate  # On Linux/macOS

# Install requirements
pip install -r requirements.txt

# Copy and configure monitor_config.json
cp monitor_config.json.example monitor_config.json
# Edit monitor_config.json to add your app IDs and settings

# Run the monitor
python sidequest_monitor.py
```

## Cronjob Example

> **Note:** When running as a cronjob or scheduled task, use the `--cron` flag to ensure all logs are written only to `sidequest_monitor.log` and not to stdout/stderr. This prevents cron from sending emails or cluttering the console with output.

### Linux/macOS (cron)
```
0 * * * * /path/to/.venv/bin/python /path/to/sidequest_monitor.py --cron
```

### Windows (Task Scheduler)
- Create a new task.
- Set the action to run: `C:\path\to\.venv\Scripts\python.exe C:\path\to\sidequest_monitor.py --cron`
- Set your preferred schedule.

## Configuration
Edit `monitor_config.json` to specify which app IDs to monitor and where to save APKs. See `monitor_config.json.example` for the required structure and options.

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
