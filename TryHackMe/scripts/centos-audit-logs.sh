#!/bin/bash

# Define log files
messages_log="/var/log/messages"
secure_log="/var/log/secure"

# Check which log file exists on the system
if [ -f "$secure_log" ]; then
    auth_log_file="$secure_log"
else
    echo "No suitable authentication log file found. Exiting."
    exit 1
fi

if [ -f "$messages_log" ]; then
    system_log_file="$messages_log"
else
    echo "No suitable system log file found. Exiting."
    exit 1
fi

# Function to find failed login attempts
failed_login_attempts() {
    echo "Failed login attempts:"
    grep -i "Failed password" "$auth_log_file" | awk '{print $1" "$2" "$3" - User: "$9" - IP: "$11}'
}

# Function to find newly added users
new_users() {
    echo "New users added:"
    grep -i "new user" "$system_log_file" | awk '{print $1" "$2" "$3" - User: "$8" - UID: "$10}'
}

# Call the functions
failed_login_attempts
echo ""
new_users
