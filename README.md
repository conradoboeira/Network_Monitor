# Network_Monitor

Two monitoring tools developed in Python 3.8.5 for a CS class. One tool performs passive monitoring, collecting statistics from packets flowing through the host, and the other can scan a subnet looking for open ports and online hosts

## Passive Monitor

Use:

```bash
python monitor.py
```

Exhibit information about packets headers and by the end of the execution, shows statistics about total number of packets, largest and smallest packet, percentage of packets for each protocol monitored and the combination of IPs that most send and received messages.

## Active Monitor 

Use: 
```bash
python scan_net.py <subnet> <min port> <max port>
```
Where subnet is the network in CIDR notation to scan and min and max port define the interval of ports to scan. 
