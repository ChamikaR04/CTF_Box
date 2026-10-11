# CyberVault CTF Platform

CyberVault is a six-stage Capture the Flag (CTF) training environment for the IE3132 Penetration Testing assignment.

## Challenges

| Stage | Challenge | Port or service |
|---|---|---|
| CV-01 | Image metadata investigation | Flask, 8080 |
| CV-02 | FTP network investigation | FTP, 21 |
| CV-03 | Web Gateway SQL injection | HTTP, 5000 |
| CV-04 | Encrypted note investigation | Flask, 8080 |
| CV-05 | Evidence image investigation | Flask, 8080 |
| CV-06 | SUID privilege escalation | SSH, 2222 |

## Architecture

The platform runs on an Ubuntu Server VM, and Kali Linux is used as the testing client.
The current Host-Only IP is 192.168.56.107; your address may differ.
Keep all intentionally vulnerable services on an isolated Host-Only network.

## Project structure

- app.py: main Flask application
- templates/: HTML templates
- static/challenge-files/: challenge assets
- CV-02/: FTP configuration and setup script
- cybervault/: Docker-based CV-03 and CV-06 challenges

## Deployment

The main Flask platform listens on port 8080.
CV-02 uses port 21, CV-03 uses port 5000, and CV-06 uses port 2222.
See cybervault/README.md for Docker deployment and testing instructions.

## Important security notes

This project intentionally contains vulnerable applications for authorized educational testing.
Do not expose the lab to the public internet.
Never commit .env files, private credentials, live databases, or personal information.
The 100 MiB CV-05 evidence image is excluded from ordinary Git commits and must be distributed separately.

Assignment: IE3132 Penetration Testing Assignment 01, Group 22.

## CV-05 asset requirement

The `static/challenge-files/cv05_evidence.img` file is excluded from Git because it is 100 MiB. Obtain this challenge asset separately from the authorized project distribution or assignment materials. Without it, CV-05 cannot be completed as configured.
