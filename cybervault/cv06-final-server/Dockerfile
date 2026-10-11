# CyberVault - CV-06 Final Server
# Intentionally vulnerable Ubuntu container for a controlled CTF environment.
# Vulnerability: SUID bit set on /usr/bin/python3.9 (a real-world common
# misconfiguration) allowing a low-privileged user to spawn a root shell.
# FOR USE ONLY INSIDE THE ISOLATED CTF NETWORK.

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y openssh-server sudo python3 python3.10 && \
    mkdir /var/run/sshd

# Low-privileged participant account
RUN useradd -m -s /bin/bash analyst && \
    echo "analyst:CyberVault2026" | chpasswd

# The flag - only root can read it
RUN echo "CV{final_server_suid_python_root_shell}" > /root/flag.txt && \
    chmod 600 /root/flag.txt

# --- INTENTIONAL MISCONFIGURATION ---
# SUID bit set on the python3 interpreter: a real GTFOBins-style privesc.
# Do not "fix" this; it is the designed vulnerability for this stage.
RUN chmod u+s /usr/bin/python3.10

# Allow SSH password auth for lab use
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
