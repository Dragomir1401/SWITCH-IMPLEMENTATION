#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    # dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        print("VLAN TAGGED PACKET")
        print("ETHERTYPE: 0x8200")
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]
    else:
        print("ETHERTYPE: " + str(ether_type))

    return dest_mac, src_mac, ether_type, vlan_id


def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)


def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)


def read_switch_config(switch_id, switch_config):
    # TODO Read the switch configuration file
    # read the switch configuration file from ./configs/switchX.config where X is the switch number
    # structure of the file:
    # PRIORITY
    # INTERFACE_NAME [VLAN_ID / TRUNK]

    # open the file for the switch id
    file = open("./configs/switch" + str(switch_id) + ".cfg", "r")

    # read the priority on the first line
    priority = file.readline()

    # define increasing interface id
    interface_id = 0

    # parse every line with the interface name and vlan id or trunk type and store it in the switch_config
    for line in file:
        # pass first line
        if line == priority:
            continue

        # split the line into the interface name and vlan id or trunk type
        interface_name, vlan_id_or_trunk_type = line.split()

        # add the interface name and vlan id or trunk type to the switch_config
        switch_config[interface_id] = vlan_id_or_trunk_type

        # increase the interface id
        interface_id += 1


def forward_with_learning(src_mac, dst_mac, vlan_id, interface, ethertype, mac_cam_table, switch_config, data, length, interfaces):
    # add the src_mac to the mac_cam_table if it is not already there
    if src_mac not in mac_cam_table:
        mac_cam_table[src_mac] = interface

    # if the type of packet is unicast, then forward the packet to the interface
    # that is in the mac_cam_table
    if dst_mac in mac_cam_table:
        # make a copy of the packet
        data_copy = data
        length_copy = length
        # modify packet if necessary
        data_copy, length_copy = modify_packet(
            vlan_id, mac_cam_table[dst_mac], switch_config, data_copy, length_copy, interfaces, ethertype, interface)
        # send the packet to the interface that is in the mac_cam_table if it is trunk type or same vlan
        if switch_config[mac_cam_table[dst_mac]] == "T" or vlan_id == int(switch_config[mac_cam_table[dst_mac]]):
            print("Sending packet to interface " +
                  str(mac_cam_table[dst_mac]))
            send_to_link(mac_cam_table[dst_mac], data_copy, length_copy)
        # else if we receive from access and send to access
        elif vlan_id == -1 and int(switch_config[mac_cam_table[dst_mac]]) == int(switch_config[interface]):
            print("Sending packet to interface " +
                  str(mac_cam_table[dst_mac]))
            send_to_link(mac_cam_table[dst_mac], data_copy, length_copy)
    else:
        # if the type of packet is broadcast, then forward the packet to all
        # interfaces except the one that received the packet
        for i in interfaces:
            if i != interface:
                # make a copy of the packet
                data_copy = data
                length_copy = length
                # modify packet if necessary
                data_copy, length_copy = modify_packet(vlan_id, i, switch_config,
                                                       data_copy, length_copy, interfaces, ethertype, interface)
                # send the packet to the interface if it is trunk type or same vlan
                if switch_config[i] == "T" or vlan_id == int(switch_config[i]):
                    print("Sending packet to interface " + str(i))
                    send_to_link(i, data_copy, length_copy)
                # else if we receive from access and send to access
                elif vlan_id == -1 and int(switch_config[i]) == int(switch_config[interface]):
                    print("Sending packet to interface " + str(i))
                    send_to_link(i, data_copy, length_copy)


def modify_packet(vlan_id, dst_interface, switch_config, data, length, interfaces, ethertype, src_interface):
    if dst_interface in interfaces:
        # if the packet is coming from access port
        if vlan_id == -1:
            print("Received packet from access port")
            # if the interface is trunk type
            if switch_config[dst_interface] == "T":
                print("Adding vlan tag " +
                      switch_config[src_interface] + " to the packet and sending it to trunk port")
                # add the vlan tag to the packet
                data = data[0:12] + \
                    create_vlan_tag(
                        int(switch_config[src_interface])) + data[12:]
                # increase the length of the packet
                length += 4
        # if the packet is coming from trunk port
        else:
            print("Received packet from trunk port")
            # if the interface is access type then remove the vlan tag
            if switch_config[dst_interface] != "T":
                print("Removing vlan tag from the packet and sending it to access port")
                # remove the vlan tag from the packet
                data = data[0:12] + data[16:]
                # decrease the length of the packet
                length -= 4

    return data, length


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    # print the switch id
    print("SWITCH ID: " + str(switch_id))

    # make mac CAM table for the switch
    mac_cam_table = {}

    # create teh sitch configuration dictionary
    switch_config = {}

    # read the switch configuration file
    read_switch_config(switch_id, switch_config)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # print the switch configuration in human readable format
    print("[INFO] Switch configuration")
    for interface_name, vlan_id_or_trunk_type in switch_config.items():
        print(get_interface_name(interface_name) + " :: " + "interface number: " + str(interface_name) +
              " vlan id or trunk type: " + str(vlan_id_or_trunk_type))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        print("Received frame of size {} on interface {}".format(
            length, interface), flush=True)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print()
        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')
        print(f'VLAN ID: {vlan_id}')
        print("Received frame of size {} on interface {}".format(
            length, interface), flush=True)

        # TODO: Implement forwarding with learning
        forward_with_learning(src_mac, dest_mac, vlan_id, interface,
                              ethertype, mac_cam_table, switch_config, data, length, interfaces)
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, data, length)


if __name__ == "__main__":
    main()
