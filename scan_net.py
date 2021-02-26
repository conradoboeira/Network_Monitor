# Author: Conrado Boeira
# Based on icmpsender2.py from https://moodle.pucrs.br/mod/folder/view.php?id=1529512

import socket, sys
import struct
from time import sleep
import time
import ipaddress
import binascii

arp_time_th = 0.5
recv_time_th = 0.5
udp_time_th = 0.5
icmp_time_th = 0.5
ping_time_th = 5
ETH_P_ALL = 0x0003

# 16-bit one's complement of the one's complement sum of the ICMP message starting with the Type field
# the checksum field should be cleared to zero before generating the checksum
def checksum(msg):
    s = 0
    # add padding if not multiple of 2 (16 bits)
    msg = (msg + b'\x00') if len(msg)%2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

# Calculate all address in the subnet given
def calc_all_addr(cidr):
    all_ips = [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    return all_ips[1:-1] # Filter out subnet address and broadcast address

def main(cidr,min_port,max_port):

    my_ip = socket.gethostbyname(socket.gethostname())

    # HORIZONTAL SCAN PART #
    ########################
    print("\n******* HORIZONTAL SCAN *******\n")
    addr_list = calc_all_addr(cidr)
    found_addr = [] #List of active hosts found
    # Local Network
    if(my_ip in addr_list):
        # Create socket
        try:
            s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except OSError as msg:
            print('Error'+str(msg))
            sys.exit(1)
        s.bind(('eth0',0))


        source_mac = s.getsockname()[4]
        dest_mac = binascii.unhexlify('ff:ff:ff:ff:ff:ff'.replace(':', ''))
        source_ip = my_ip

        # Part taken from https://dk0d.blogspot.com/2016/07/code-for-sending-arp-request-with-raw.html

        # Ethernet Header
        protocol = 0x0806                       # 0x0806 for ARP
        eth_hdr = struct.pack("!6s6sH", dest_mac, source_mac, protocol)

        # ARP header
        htype = 1                               # Hardware_type ethernet
        ptype = 0x0800                          # Protocol type TCP
        hlen = 6                                # Hardware address Len
        plen = 4                                # Protocol addr. len
        operation = 1                           # 1=request/2=reply
        src_ip = socket.inet_aton(source_ip)

        print("Checking network addresses with ARP probe")
        # Iterate through all possible addresses
        for ip in addr_list:
            if(ip == my_ip): continue

            print("Checking IP: {}".format(ip), end='')

            # Send packet
            dst_ip = socket.inet_aton(ip)
            arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, operation, source_mac, src_ip, dest_mac, dst_ip)
            packet = eth_hdr + arp_hdr
            s.send(packet)

            # check for response
            s.settimeout(arp_time_th)
            try:
                (rec_packet,addr) = s.recvfrom(65536)
            #if timeout out, consider host inactive
            except socket.timeout:
                print(" -> inactive")
                continue
            r_eth_len = 14
            r_eth_header = rec_packet[:14]

            r_eth = struct.unpack("!6s6sH", r_eth_header)

            # Check if it is an ARP packet
            if r_eth[2] == 0x0806:
                arp_header = rec_packet[r_eth_len:28+r_eth_len]
                aph = struct.unpack("!HHBBH6s4s6s4s", arp_header)
                opcode = aph[4]
                #Check if it is a response
                if(opcode == 2):
                    print(" -> ACTIVE")
                    r_src_mac = bytes_to_mac(aph[5])
                    r_src_ip = socket.inet_ntoa(aph[6])
                    found_addr.append(r_src_ip)

        s.close()


    # Outside Network
    else:

        #Create socket to send icmp
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except OSError as msg:
            print('Error'+str(msg))
            sys.exit(1)

        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)

        #Create socket to receive
        try:
            r = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        except OSError as msg:
            print('Error'+str(msg))
        r.bind(('eth0',0))

        # ICMP Header
        type = 8
        code = 0
        mychecksum = 0
        identifier = 12345
        seqnumber = 0

        # Set payload to have the desired amount of bytes
        payload = b""
        for i in range(1000):
            payload += b"d"

        # Pack ICMP header fields
        icmp_packet = struct.pack("!BBHHH%ds"%len(payload), type, code, mychecksum, identifier, seqnumber, payload)

        # Calculate checksum
        mychecksum = checksum(icmp_packet)

        # Repack with checksum
        icmp_packet = struct.pack("!BBHHH%ds"%len(payload), type, code, mychecksum, identifier, seqnumber, payload)

        # Header IP
        ip_ver = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = 0 # automaticamente preenchido - AF_INET
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_ICMP
        ip_check = 0  # automaticamente preenchido - AF_INET
        ip_ihl_ver = (ip_ver << 4) + ip_ihl


        print("Checking network addresses with ICMP Request probe")
        # Iterate through all possible addresses
        for ip in addr_list:
            if(ip == my_ip): continue

            print("Checking IP: {}".format(ip), end='')

            dst_ip = socket.inet_aton(ip)
            src_ip = socket.inet_aton(my_ip)
            ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, src_ip,dst_ip)
            packet = ip_header+icmp_packet

            s.sendto(packet, (ip,0))
            send_time = time.time()

            done = False
            # Try until timeout or received a reply ou a Unreachable message
            while((time.time()-send_time) < ping_time_th and not done):

                # check for response
                s.settimeout(icmp_time_th)
                try: (rec_packet,addr) = s.recvfrom(65536)
                except socket.timeout as e: continue

                ip_header = rec_packet[:20]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl*4
                ttl = iph[5]
                protocol_num = iph[6]

                #Check if it is an ICMP packet
                if(protocol_num == 1):
                    r_icmp_header = rec_packet[iph_length:8+iph_length]
                    r_icmph = struct.unpack("!BBHHH",r_icmp_header)
                    icmp_type_num = int(r_icmph[0])
                    icmp_code = int(r_icmph[1])

                    #Check if it is a reply
                    if(icmp_type_num == 0 and icmp_code == 0):
                        resp_time = time.time()
                        diff_time = resp_time - send_time
                        done = True
                        print(" -> ACTIVE  RTT: {:f} msec".format(diff_time*1000 ))
                        r_src_ip = socket.inet_ntoa(iph[8])
                        found_addr.append(r_src_ip)
                    #Check if it is any Unreachable message
                    elif(icmp_type_num == 3):
                        resp_time = time.time()
                        diff_time = resp_time - send_time
                        done = True
                        print(" -> inactive RTT: {:f} msec".format(diff_time*1000 ))
        s.close()
        r.close()


    # VERTICAL SCAN PART #
    ######################
    print("\n******* VERTICAL SCAN *******\n")

    #Create socket to send TCP packets
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    #Create socket to send UDP packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #Create socket to receive icmp packets
    try:
        i = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)
    i.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)



    # Iterate through all possible addresses
    for ip in found_addr:
        if(ip == my_ip): continue


        dst_ip = socket.inet_aton(ip)
        src_ip = socket.inet_aton(my_ip)

        # Iterate through all ports in range
        for port in range(min_port, max_port+1):
            print("Checking {}:{}".format(ip,port))

            print("TCP:", end='')

            #Try to establish a TCP connection
            active_tcp = True
            try:
                s.connect((ip,port))
            except Exception as e:
                active_tcp = False
                print(" -> inactive")

            if(active_tcp):
                print(" -> ACTIVE")
                s.close()

            #Send UDP packet
            print("UDP:", end='')
            sent = sock.sendto("test".encode('utf-8'), (ip,port))
            sent_time = time.time()

            done = False
            # Wait until timeout or received a Port Unreachable packet
            while((time.time() - sent_time) < udp_time_th and not done):
                # check for response
                i.settimeout(udp_time_th)
                try: (rec_packet,addr) = i.recvfrom(65536)
                except socket.timeout as e: continue

                ip_header = rec_packet[:20]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl*4
                ttl = iph[5]
                protocol_num = iph[6]

                #Check if it is an ICMP packet
                if(protocol_num == 1):
                    len_prev_head = iph_length
                    r_icmp_header = rec_packet[len_prev_head:8+len_prev_head]
                    r_icmph = struct.unpack("!BBHHH",r_icmp_header)
                    icmp_type_num = int(r_icmph[0])
                    icmp_code = int(r_icmph[1])
                    #Check if its a Port Unreachable message
                    if(icmp_type_num == 3 and icmp_code == 3):
                        done = True
                        print(" -> inactive" )
            if(not done):
                print(" -> ACTIVE")



if __name__ == '__main__':
    cidr = sys.argv[1]
    min_port = int(sys.argv[2])
    max_port = int(sys.argv[3])
    main(cidr, min_port, max_port)
