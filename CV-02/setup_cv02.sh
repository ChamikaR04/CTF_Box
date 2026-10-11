#!/bin/bash
# CV-02 Network Trail: setup on a fresh Ubuntu Server 22.04
# Usage: sudo ./setup_cv02.sh 'CV{flag_value}'
set -e
FLAG="$1"
[ -z "$FLAG" ] && { echo "Usage: sudo $0 'CV{flag}'"; exit 1; }
hostnamectl set-hostname fileserver-02
sed -i 's/^127.0.1.1.*/127.0.1.1 fileserver-02/' /etc/hosts
apt update && apt install -y vsftpd
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
cp "$(dirname "$0")/vsftpd.conf" /etc/vsftpd.conf
mkdir -p /srv/ftp
echo "$FLAG" > /srv/ftp/flag.txt
chmod 755 /srv/ftp
chmod 644 /srv/ftp/flag.txt
systemctl enable --now vsftpd
systemctl disable --now ssh 2>/dev/null || true
echo "CV-02 ready: anonymous FTP on port 21, SSH off."
