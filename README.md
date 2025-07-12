# SioSnortProject

# Network Intrusion Detection System Project Using Snort 3

# Objective

Set up and configure a Network Intrusion Detection System (NIDS) using Snort 3 to monitor network traffic, detect suspicious or malicious activity, implement response mechanisms, and visualize detected attacks.

# Prerequisites

Snort 3 installed on a Linux system (e.g., Ubuntu 20.04 or later).
Administrative (root) privileges.
Network interface connected to the network to monitor.
Basic understanding of networking and Linux commands.

# Step 1: Configure Snort 3

Locate Configuration Files:

Snort 3 configuration files are typically in /etc/snort or /usr/local/etc/snort.
Main configuration file: snort.lua (default configuration).

Edit snort.lua:

Open the configuration file: sudo nano /etc/snort/snort.lua

Set the network interface to monitor (e.g., eth0):HOME_NET = '192.168.1.0/24' -- Replace with your network range

EXTERNAL_NET = '!$HOME_NET' or "any"

Enable the daq module and specify the interface:
daq = { module = 'afpacket', interfaces = 'eth0' }

Configure output for alerts:alert_csv =  
{ file = 'alert.csv', fields = 'pkt_num proto src_addr src_port dst_addr dst_port sig_id msg' }

Verify Configuration:

Test the configuration: 
sudo snort -c /etc/snort/snort.lua --lua "ips = { enable_builtin_rules = true }" -i eth0 -k none
"Ensure no errors are reported."

# Step 2: Configure Rules and Alerts

Obtain Snort Rules:

Use community rules or register at Snort.org for subscriber rules.

Download community rules:wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz

tar -xvzf snort3-community-rules.tar.gz -C /etc/snort/rules

Include Rules in snort.lua:

Add the rules directory to snort.lua:

ips = {
    rules = [[ include /etc/snort/rules/snort3-community-rules/snort3-community.rules ]],
    enable_builtin_rules = true
}

Create Custom Rules:

Create a file for custom rules: sudo nano /etc/snort/rules/local.rules


Example rule to detect ICMP ping: alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)


Include in snort.lua: 
    ips.rules = [[ include /etc/snort/rules/snort3-community-rules/snort3-community.rules include /etc/snort/rules/local.rules ]]

Test Rules:

Run Snort in test mode:  sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast


Generate ICMP traffic (e.g., ping 192.168.1.1) and verify alerts in the console.

# Step 3: Monitor Network Traffic

Run Snort in NIDS Mode:

Start Snort to monitor traffic continuously:   sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_csv -k none


Alerts are logged to alert.csv in the working directory.


Monitor Logs:

Check alert.csv for detected events:  cat alert.csv


Example output:pkt_num,proto,src_addr,src_port,dst_addr,dst_port,sig_id,msg
1,ICMP,192.168.1.100,,192.168.1.1,,1000001,ICMP Ping Detected

# Step 4: Implement Response Mechanisms

Basic Alerting:

Snort’s alert_csv output serves as the primary alerting mechanism.

Optionally, redirect alerts to a file or syslog:alert_syslog = { }


Automated Response with Scripts:

Create a script to process alerts and take actions (e.g., block IP with iptables).

Example script (block_ip.sh): 

#!/bin/bash
tail -f alert.csv | while read line; do
    SRC_IP=$(echo $line | cut -d',' -f3)
    if [[ ! -z "$SRC_IP" && "$SRC_IP" != "src_addr" ]]; then
        sudo iptables -A INPUT -s $SRC_IP -j DROP
        echo "Blocked IP: $SRC_IP"
    fi
done

Save as /etc/snort/block_ip.sh, make executable:  chmod +x /etc/snort/block_ip.sh

Run:sudo /etc/snort/block_ip.sh

Test Response:

Generate malicious traffic (e.g., nmap scan or ping flood).

Verify that the source IP is blocked:sudo iptables -L


# Step 5: Visualize Detected Attacks

Use ELK Stack for Visualization:


Install Elasticsearch, Logstash, and Kibana (ELK) to visualize Snort alerts.

Basic Logstash configuration to parse alert.csv:

input {
    file {
        path => "/path/to/alert.csv"
        start_position => "beginning"
    }
}
filter {
    csv {
        columns => ["pkt_num", "proto", "src_addr", "src_port", "dst_addr", "dst_port", "sig_id", "msg"]
    }
}
output {
    elasticsearch {
        hosts => ["localhost:9200"]
        index => "snort_alerts"
    }
}

Save as /etc/logstash/conf.d/snort.conf.


Create Kibana Dashboard:

Access Kibana (default: http://localhost:5601).

Create an index pattern for snort_alerts

Build visualizations (e.g., pie chart for protocols, timeline for alerts).

Example: Create a bar chart showing alerts by msg field.
