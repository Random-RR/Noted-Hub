# NoterTwo 

## Introduction

NoterTwo is an Easy Linux machine that show cases a Note-taking application that includes a CVE in dompdf that exploits a php deserialization attack which allows  users to overwrite a `.htaccess` file allowing users to download arbitrary files from a restricted file server. This gives users a ssh key to login as a certain user. Once in the server, there is an encrypted password file (of that same user) which the players will have to decrypt using the ssh key they got. For root, we exploit yet another CVE in GZIP that allows users to get command injection as the root user. 

---

## Info for HTB

### Access

System passwords:

| username   | password                  |
| ---------- | ------------------------- |
| sysadm_acc | `8S*SA&5AS^1(AS!H2`       |
| ftp_admin  | `thisistheftp_admin123!#` |
| root       | `s12ikhlksp12hjko2hs33`   |


### Key processes

- Apache is running on port 80, Openssh is running on port 22, vsFTPd is running on port 21

### Automation

- There are 2 crons running to cleanup the file vhost root directory and the php web application

```
*/10 * * * * /root/scripts/cron/web_cleanup.sh
* * * * * /root/scripts/cron/file_cleanup.sh
```

- `web_cleanup.sh`

```bash
#!/bin/sh
rm -r /root/scripts/docker/web/*
cp -r /root/scripts/cron/web/* /root/scripts/docker/web/

```

- `file_cleanup.sh`

```bash
#!/bin/sh
rm -r /var/www/files/.htaccess
rm -r /var/www/files/*
cp -r /root/scripts/cron/files/* /var/www/files/
cp -r /root/scripts/cron/files/.htaccess /var/www/files/.htaccess

```

> This one is needed to run *at least* once every minute, as this restores the `.htaccess` file in the files vhost so that the files are not visible to the users without exploiting the php serialization vulnerability.

### Docker

- There is one docker container running the php application

```yml
version: '3'

services:
  web:
    image: php:7.4-cli
    volumes:
    - /srv/ftp/:/srv/ftp
    - ./web:/app
    - /var/www/files:/var/www/files
    ports:
      - "127.0.0.1:8080:8080"
    cap_drop:
      - MKNOD
    working_dir: /app
    command: /usr/local/bin/php -S 0.0.0.0:8080 /app/index.php

```

### Services

- A systemd service is installed to the docker container on startup. (`docker-apps.service`)

```service
[Unit]
Description=Docker Compose Application Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/root/scripts/docker
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```