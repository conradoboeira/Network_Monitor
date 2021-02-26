# Author: Conrado Boeira
import socket
import sys
import struct
import time
import signal

ETH_P_ALL = 0x0003

# Stats vars
total_packets = 0
max_packet = -1
min_packet = -1
proto_count = {"ARP":0, "IP":0, "ICMP":0, "TCP":0, "UDP":0, "Undefined":0}
ip_send_count = {}
ip_receive_count = {}
ip_pair_count = {}
port_send_count = {}
port_receive_count = {}


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

def signal_handler(signal, frame):
    print("\n ********* STATS *********\n")
    print("Total packets captured: {}".format(total_packets))
    print("Largest packet captured: {} bytes".format(max_packet))
    print("Smallest packet captured: {} bytes".format(min_packet))

    print("\nPercentage of packets per each protocol")
    for proto in proto_count:
        print("{} : {:0.3f}%".format(proto, (proto_count[proto]/total_packets)*100))

    print("\nIPs that send the most amount of packets")
    sent = sorted(ip_send_count.items(), key=lambda x: x[1], reverse=True)
    index = 0
    for ip in sent:
        if(index >= 5): break
        print("{} -> {} packets".format(ip[0], ip[1]))
        index += 1

    print("\nIPs that received the most amount of packets")
    received = sorted(ip_receive_count.items(), key=lambda x: x[1], reverse=True)
    index = 0
    for ip in received:
        if(index >= 5): break
        print("{} -> {} packets".format(ip[0],ip[1]))
        index+=1


    print("\nPair of IPs that exchanged the most amount of packets")
    pair = sorted(ip_pair_count.items(), key=lambda x: x[1], reverse=True)
    index = 0
    for ip in pair:
        if(index >= 5): break
        print("{} x {} -> {} packets".format(ip[0][0],ip[0][1], ip[1]))
        index+=1

    if(proto_count["TCP"] > 0 or proto_count["UDP"] > 0):
        print("\nPort that sent the most amount of packets: {}".format(max(port_send_count, key=port_send_count.get)))
        print("Port that received the most amount of packets: {}".format(max(port_receive_count, key=port_receive_count.get)))
    sys.exit(0)

def main():
    global total_packets, max_packet, min_packet

    signal.signal(signal.SIGINT, signal_handler)

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)


    #s.bind(('eth0',0))
    while(True):
        (packet,addr) = s.recvfrom(65536)

        total_packets += 1
        if(len(packet) > max_packet or max_packet == -1):
            max_packet = len(packet)
        if(len(packet) < min_packet or min_packet == -1):
            min_packet = len(packet)

        eth_length = 14
        eth_header = packet[:14]

        print("\n****** NEW PACKET ******")
        eth = struct.unpack("!6s6sH",eth_header)
        dst_mac = bytes_to_mac(eth[0])
        src_mac = bytes_to_mac(eth[1])
        packet_type = 'Undefined'
        if(eth[2] == 0x0800):
            packet_type = "IP"
        elif(eth[2] == 0x0806):
            packet_type = "ARP"

        print("Ethernet Header Info:")
        print("Source MAC Address: {}".format(src_mac))
        print("Destination MAC Address: {}".format(dst_mac))
        print("Packet Type: {}".format(packet_type))

        proto_count[packet_type] += 1

        if(packet_type == "IP"):
            ip_header = packet[eth_length:20+eth_length]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl*4
            ttl = iph[5]
            protocol_num = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            if(s_addr not in ip_send_count): ip_send_count[s_addr] = 1
            else: ip_send_count[s_addr] +=1

            if(d_addr not in ip_receive_count): ip_receive_count[d_addr] = 1
            else: ip_receive_count[d_addr] +=1

            addr_pair = (s_addr,d_addr)
            if(addr_pair not in ip_pair_count): ip_pair_count[addr_pair] = 1
            else: ip_pair_count[addr_pair] +=1

            protocol = 'Undefined'
            if(int(protocol_num) == 1): protocol = "ICMP"
            elif(int(protocol_num) == 6): protocol = "TCP"
            elif(int(protocol_num) == 17): protocol = "UDP"

            print("------------------------------------")
            print("IP Header Info:")
            print("Source IP Address: {}".format(s_addr))
            print("Destination IP Address: {}".format(d_addr))
            print("Time To Live: {}".format(ttl))
            print("Encapsulated Protocol: {}".format(protocol))

            len_prev_head = eth_length + iph_length

            proto_count[protocol] += 1

            if(protocol == "ICMP"):
                icmp_header = packet[len_prev_head:8+len_prev_head]
                icmph = struct.unpack("!BBHHH",icmp_header)
                icmp_type_num = icmph[0]
                icmp_code = icmph[1]
                icmp_type = "Undefined"
                if(icmp_type_num == 0 and icmp_code == 0):
                    icmp_type = "Echo Reply"

                elif(icmp_type_num == 3):
                    if(icmp_code == 0): icmp_type = "Network Unreachable"
                    elif(icmp_code == 1): icmp_type = "Host Unreachable"
                    elif(icmp_code == 2): icmp_type = "Protocol Unreachable"
                    elif(icmp_code == 3): icmp_type = "Port Unreachable"

                elif(icmp_type_num == 8 and icmp_code == 0):
                    icmp_type = "Echo Request"

                print("------------------------------------")
                print("ICMP Header Info:")
                print("ICMP Type: {}".format(icmp_type))

                if(icmp_type == "Echo Request" or icmp_type == "Echo Reply"):
                    icmp_id = icmph[3]
                    icmp_seq = icmph[4]
                    payload = packet[8+len_prev_head:]
                    print("ICMP ID: {}".format(icmp_id))
                    print("ICMP Sequence Number: {}".format(icmp_seq))
                    print("Payload:")
                    print(payload.decode('ascii'))

            elif(protocol == "TCP" or protocol == "UDP"):
                ports = packet[len_prev_head:4+len_prev_head]
                ports_h = struct.unpack("!HH",ports)
                src_port = ports_h[0]
                dst_port = ports_h[1]

                if(src_port not in port_send_count): port_send_count[src_port] = 1
                else: port_send_count[src_port] +=1

                if(dst_port not in port_receive_count): port_receive_count[dst_port] = 1
                else: port_receive_count[dst_port] +=1

                print("------------------------------------")
                if(protocol == "TCP"): print("TCP Header Info:")
                else: print("UDP Header Info:")
                print("Source Port: {}".format(src_port))
                print("Destination Port: {}".format(dst_port))


        elif(packet_type == "ARP"):
            arp_header = packet[eth_length:28+eth_length]
            aph = struct.unpack("!HHBBH6s4s6s4s", arp_header)

            opcode = aph[4]
            arp_type = "Undefined"
            if(opcode == 1): arp_type = "Request"
            elif(opcode == 2): arp_type = "Response"

            src_mac = bytes_to_mac(aph[5])
            src_ip = socket.inet_ntoa(aph[6])
            dst_mac = bytes_to_mac(aph[7])
            dst_ip = socket.inet_ntoa(aph[8])

            if(src_ip not in ip_send_count): ip_send_count[src_ip] = 1
            else: ip_send_count[src_ip] +=1

            if(dst_ip not in ip_receive_count): ip_receive_count[dst_ip] = 1
            else: ip_receive_count[dst_ip] +=1

            addr_pair = (src_ip,dst_ip)
            if(addr_pair not in ip_pair_count): ip_pair_count[addr_pair] = 1
            else: ip_pair_count[addr_pair] +=1

            print("------------------------------------")
            print("ARP Header Info:")
            print("ARP Type: {}".format(arp_type))
            print("ARP Source MAC Address: {}".format(src_mac))
            print("ARP Source IP Address: {}".format(src_ip))
            print("ARP Destination MAC Address: {}".format(dst_mac))
            print("ARP Destination IP Address: {}".format(dst_ip))

if __name__ == '__main__':
    main()
