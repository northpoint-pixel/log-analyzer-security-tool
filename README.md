# Log Analyzer / Security Alert Tool

A Python-based security log analyzer that detects failed login attempts, suspicious IP activity, warnings, and errors.

## Features

- Reads a log file
- Detects failed login attempts
- Extracts IP addresses from suspicious entries
- Flags repeated failed login attempts by IP
- Assigns severity levels based on repeated failures
- Saves analysis results as JSON

## Tech Stack

- Python 3
- Regular expressions
- JSON

## Purpose

This project was built to demonstrate practical log analysis, incident detection, and alerting skills relevant to IT support, system administration, and entry-level cybersecurity roles.

## Project Structure

```bash
log-analyzer-security-tool/
├─ README.md
├─ .gitignore
├─ requirements.txt
├─ analyzer/
│  ├─ analyzer.py
│  └─ patterns.py
├─ logs/
│  └─ sample_auth.log
├─ results/
├─ docs/