#!/bin/bash
# Ubuntu

# CHECK Authentication logs
cat /var/log/auth.log | tail

# CHECK EVIDENCE OF COMMAND EXECUTION
cat /var/log/auth.log* |grep -i COMMAND| tail

# Check Bash history
cat ~/.bash_history

# Check Files accessed using vim
cat ~/.viminfo

# Check host about system activity
cat /var/log/syslog* | head
