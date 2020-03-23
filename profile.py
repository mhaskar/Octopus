#!/usr/bin/python3

# this is the web listener profile for Octopus C2
# you can customize your profile to handle a specific URLs to communicate with the agent
# TODO : add the ability to customize the request headers

# handling the file downloading
# Ex : /anything
# Ex : /anything.php
file_receiver_url = "/messages"


# handling the report generation
# Ex : /anything
# Ex : /anything.php
report_url = "/calls"

# command sending to agent (store the command will be executed on a host)
# leave <hostname> as it with the same format
# Ex : /profile/<hostname>
# Ex : /messages/<hostname>
# Ex : /bills/<hostname>
command_send_url = "/view/<hostname>"


# handling the executed command
# Ex : /anything
# Ex : /anything.php
command_receiver_url = "/bills"


# handling the first connection from the agent
# Ex : /anything
# Ex : /anything.php
first_ping_url = "/login"

# will return in every response as Server header
server_response_header = "nginx"

# will return white page that includes HTA script
mshta_url = "/hta"

# auto kill value after n tries

auto_kill = 10
