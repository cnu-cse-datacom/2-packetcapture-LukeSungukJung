import socket   
import struct

recv_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))

tcp_data =recv_socket.recvfrom(65565)
print(tcp_data[0])


def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s",data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dst = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()
    
    print("===========ethernet============")
    print("src_mac_address:",ether_src)
    print("dst_mac_address:",ether_dst)
    print("ip_version:",ip_header)
    

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr =":".join(ethernet_addr)
    return ethernet_addr


def sixteen_to_ten(data):
    alist = list()
    for s in data:
        alist.append(str(int(s,16)))

    ip_addr= ".".join(alist)
    return ip_addr

def convert_ip_address_list(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(i.hex())
    return ip_addr

def parsing_ip_header(data):
    network_header = struct.unpack("!2c1h2s2s1c1c2s4c4c",data)
    print("=============ip header==============")
    ip_version = int(network_header[0].hex()[0])
    ip_length = int(network_header[0].hex()[1])
    print("ip_version: ",ip_version)
    print("ip_length: ",ip_length)
    print("differentiated_service_codepoint: ",network_header[1].hex()[0])
    print("Total Length: ",network_header[2])
    print("explicit_congestion_notification: ","0x"+network_header[3].hex())
    print("Flags: ", "0x"+network_header[4].hex())
    print("Time to live: ",network_header[5].hex())
    print("Protocol: ",network_header[6].hex())
    print("Header checksum: ", "0x"+network_header[7].hex())
    src_hex_list = convert_ip_address_list(network_header[8:12])
    dst_hex_list = convert_ip_address_list(network_header[12:16])
    print("source_ip_addreses: ",sixteen_to_ten(src_hex_list))
    print("destination_ip_addreses: ", sixteen_to_ten(dst_hex_list))
    return network_header[6].hex()




def sixteen_to_ten_to_int(data):
    sum_res = int("".join(data),16)
    return sum_res



def parsing_tcp_header(data):
    transport_header = struct.unpack("!2c2c4c4c1c1c2c2c2c", data)
    src_list=[transport_header[0].hex(),transport_header[1].hex()]
    dst_list = [transport_header[2].hex(), transport_header[3].hex()]
    seq = sixteen_to_ten_to_int([a.hex() for a in transport_header[4:8]])
    ack = sixteen_to_ten_to_int([a.hex() for a in transport_header[8:12]])

    #leng_list = [transport_header[4].hex(), transport_header[5].hex()]
    print("=============tcp header==============")
    print("src_port: ",sixteen_to_ten_to_int(src_list))
    print("dec_port: ",sixteen_to_ten_to_int(dst_list))
    print("seq_num: ",seq)
    print("ack_num: ",ack)
    print("header_len: ",int(transport_header[12].hex()[0],16))
    nxt_flag_num = transport_header[12].hex()[1]
    print("flags: ",int(nxt_flag_num+transport_header[13].hex(),16))
    print("window_size: ",int( sixteen_to_ten_to_int([d.hex() for d in transport_header[14:16]])))
    print("Check_sum: ",int( sixteen_to_ten_to_int([d.hex() for d in transport_header[16:18]])))
    print("Urgent_pointer: ", int(sixteen_to_ten_to_int([d.hex() for d in transport_header[18:20]])))


def parsing_udp_header(data):
    transport_header = struct.unpack("!2c2c2c2c2s", data)
    src_list = [transport_header[0].hex(), transport_header[1].hex()]
    dst_list = [transport_header[2].hex(), transport_header[3].hex()]
    print("=============udp header==============")
    print("src_port: ",sixteen_to_ten_to_int(src_list))
    print("dec_port: ",sixteen_to_ten_to_int(dst_list))
    print("length: ", int(sixteen_to_ten_to_int([d.hex() for d in transport_header[3:5]])))
    checksum = "".join([d.hex()for d in transport_header[5:7]])
    print("header checksum: ","0x"+checksum)


#Tcp
#parsing_ethernet_header(tcp_data[0][0:14])
#pc=parsing_ip_header(tcp_data[0][14:34])
#parsing_tcp_header(tcp_data[0][34:54])

recv_socket_2 = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))
udp_data = recv_socket_2.recvfrom(65565)
#UDP
#parsing_ethernet_header(udp_data[0][0:14])
#pc=parsing_ip_header(udp_data[0][14:34])
#parsing_udp_header(udp_data[0][34:44])

def parsing_unknown(data):
    parsing_ethernet_header(tcp_data[0][0:14])
    tcp_udp=parsing_ip_header(tcp_data[0][14:34])
    if str(tcp_udp) =="06":
        parsing_tcp_header(tcp_data[0][34:54])
    else:
        parsing_udp_header(udp_data[0][34:44])
        
parsing_unknown(tcp_data)       
parsing_unknown(udp_data)
    
    