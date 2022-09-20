#!/bin/sh
#
#
# BASED ON: https://javapipe.com/iptables-ddos-protection
#
# AUTHOR: ALAA ABDULRIDHA 2020
#
############################################################
UPDATE="sysctl -p"
IPTABLES="/sbin/iptables"
SYSCTL=/etc/sysctl.conf
# Backup current sysctl.conf
echo "Backing up sysctl.conf, please wait..."
cp $SYSCTL $SYSCTL.bck

# Append new lines to your file
echo "Generating new configuration on sysctl.conf file, please wait..."
cat << EOF >> $SYSCTL

# Anti-DDoS Kernel Settings
kernel.printk = 4 4 1 7
kernel.panic = 10
kernel.sysrq = 0
kernel.shmmax = 4294967296
kernel.shmall = 4194304
kernel.core_uses_pid = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
vm.swappiness = 20
vm.dirty_ratio = 80
vm.dirty_background_ratio = 5
fs.file-max = 2097152
net.core.netdev_max_backlog = 262144
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864
net.core.somaxconn = 65535
net.core.optmem_max = 25165824
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
net.ipv4.neigh.default.gc_interval = 5
net.ipv4.neigh.default.gc_stale_time = 120
net.netfilter.nf_conntrack_max = 10000000
net.netfilter.nf_conntrack_tcp_loose = 0
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 20
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 20
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.route.flush = 1
net.ipv4.route.max_size = 8048576
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.tcp_wmem = 4096 87380 33554432
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = 400000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
EOF

# Apply new configuration
echo "Applying new sysctl configuration to your system..."
$UPDATE
# Enable IP spoofing protection
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done

# Protect against SYN flood attacks
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Ignore all incoming ICMP echo requests
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Ignore ICMP echo requests to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Log packets with impossible addresses.
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done

# Don't log invalid responses to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Don't accept or send ICMP redirects.
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done

# Disable proxy_arp.
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done

# Enable secure redirects, i.e. only accept ICMP redirects for gateways
# Helps against MITM attacks.
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done

# Disable bootp_relay
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done

echo "Please wait I'm protecting you..."

#### Your default SSH Port
SSH_PORT="22"

#### Your GameServer Ports (This will take care of RCON Blocks and Invalid Packets.
GAMESERVERPORTS="8080,80"
GAMESERVER_FIRST_PORT="8080"
GAMESERVER_SECOND_PORT="80"

#### Root IP , Is the source IP
YOUR_HOME_IP="64.225.111.80"

#### DESTINATION is the gs server ip
DESTINATION_IP="142.93.172.146"

#### UDP Ports you want to protect, 3306 (MySQL) and 64738 (Mumble) are commonly used here.
#### You can add port ranges and single Ports together as well, Example; "27015:27022,80"
UDP_PORTS_PROTECTION="8080,80,3306"

#### TCP Ports you want to protect (Remove the # if you wish to protect a few Ports, also remove the # in the actual $IPTABLES below.
#### You can add port ranges and single Ports together as well, Example; "27015:27022,80"
TCP_PORTS_PROTECTION="80,443,8080,3306"

## Allow the ipv4 forwarding
##---------------------------
## Cleanup Rules First!
##--------------------
$IPTABLES -P INPUT ACCEPT
$IPTABLES -P FORWARD ACCEPT
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -F
$IPTABLES -X
$IPTABLES -t nat -F
$IPTABLES -t nat -X
$IPTABLES -t mangle -F
$IPTABLES -t mangle -X
##--------------------
#### SSH && Home IP if Used.
#$IPTABLES -A INPUT -p tcp --dport $SSH_PORT -s $YOUR_HOME_IP -j ACCEPT
$IPTABLES -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m hashlimit --hashlimit-upto 1/sec --hashlimit-burst 20 --hashlimit-mode srcip,dstport --hashlimit-name SSHPROTECT --hashlimit-htable-expire 60000 --hashlimit-htable-max 999999999 -j ACCEPT
$IPTABLES -N LOGINVALID
# Microsoft, Drop SMB/CIFS/etc..
$IPTABLES -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
$IPTABLES -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
# Drop any traffic from IANA-reserved IPs.
#------------------------------------------------------------------------------
$IPTABLES -A INPUT -s 0.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 2.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 5.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 7.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 23.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 27.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 31.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 36.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 39.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 42.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 49.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 50.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 77.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 78.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 92.0.0.0/6 -j DROP
$IPTABLES -A INPUT -s 96.0.0.0/4 -j DROP
$IPTABLES -A INPUT -s 112.0.0.0/5 -j DROP
$IPTABLES -A INPUT -s 120.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 169.254.0.0/16 -j DROP
$IPTABLES -A INPUT -s 172.16.0.0/12 -j DROP
$IPTABLES -A INPUT -s 173.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 174.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 176.0.0.0/5 -j DROP
$IPTABLES -A INPUT -s 184.0.0.0/6 -j DROP
$IPTABLES -A INPUT -s 192.0.2.0/24 -j DROP
$IPTABLES -A INPUT -s 197.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 198.18.0.0/15 -j DROP
$IPTABLES -A INPUT -s 223.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 224.0.0.0/3 -j DROP

$IPTABLES -A INPUT -p icmp --fragment -j DROP
$IPTABLES -A OUTPUT -p icmp --fragment -j DROP
$IPTABLES -A FORWARD -p icmp --fragment -j DROP
$IPTABLES -N RELATED_ICMP
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type time-exceeded -j ACCEPT
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type parameter-problem -j ACCEPT
$IPTABLES -A RELATED_ICMP -j DROP

# Make It Even Harder To Multi-PING
$IPTABLES  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
$IPTABLES  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j LOG --log-prefix "IPTABLES: PING-DROP:"
$IPTABLES  -A INPUT -p icmp -j DROP
$IPTABLES  -A OUTPUT -p icmp -j ACCEPT
# Allow all ESTABLISHED ICMP traffic.
$IPTABLES -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT $RLIMIT
$IPTABLES -A OUTPUT -p icmp -m state --state ESTABLISHED -j ACCEPT $RLIMIT

# Allow some parts of the RELATED ICMP traffic, block the rest.
$IPTABLES -A INPUT -p icmp -m state --state RELATED -j RELATED_ICMP $RLIMIT
$IPTABLES -A OUTPUT -p icmp -m state --state RELATED -j RELATED_ICMP $RLIMIT

# Allow incoming ICMP echo requests (ping), but only rate-limited.
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j ACCEPT $RLIMIT

# Allow outgoing ICMP echo requests (ping), but only rate-limited.
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT $RLIMIT
#### Block Packets ranging from 0:28, 30:32, 46 and 2521:65535 (Never Used, thus Invalid Packets) - This will catch all DoS attempts and Invalid Packet (weak) DDoS attacks as well.

$IPTABLES -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 0:28 -j LOGINVALID
$IPTABLES -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 30:32 -j LOGINVALID
$IPTABLES -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 46 -j LOGINVALID
$IPTABLES -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 60 -j LOGINVALID
$IPTABLES -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 2521:65535 -j LOGINVALID
# Drop any other ICMP traffic.
$IPTABLES -A INPUT -p icmp -j DROP
$IPTABLES -A OUTPUT -p icmp -j DROP
$IPTABLES -A FORWARD -p icmp -j DROP

## Create Filter Rules
##---------------------
$IPTABLES -N SYN_FLOOD
$IPTABLES -A INPUT -p tcp --syn -j SYN_FLOOD
$IPTABLES -A SYN_FLOOD -m limit --limit 2/s --limit-burst 6 -j RETURN
$IPTABLES -A SYN_FLOOD -j DROP

## Create Routing rules
##---------------------
$IPTABLES -t nat -A PREROUTING -p tcp --dport $GAMESERVER_FIRST_PORT -j DNAT --to-destination $DESTINATION_IP:$GAMESERVER_FIRST_PORT
$IPTABLES -t nat -A PREROUTING -p tcp --dport $GAMESERVER_SECOND_PORT -j DNAT --to-destination $DESTINATION_IP:$GAMESERVER_SECOND_PORT
##$IPTABLES -t nat -A POSTROUTING -j MASQUERADE


echo "20000" > /proc/sys/net/ipv4/tcp_max_syn_backlog
echo "1" > /proc/sys/net/ipv4/tcp_synack_retries
echo "30" > /proc/sys/net/ipv4/tcp_fin_timeout
echo "5" > /proc/sys/net/ipv4/tcp_keepalive_probes
echo "15" > /proc/sys/net/ipv4/tcp_keepalive_intvl
echo "20000" > /proc/sys/net/core/netdev_max_backlog
echo "20000" > /proc/sys/net/core/somaxconn
echo "99999999" > /proc/sys/net/nf_conntrack_max
