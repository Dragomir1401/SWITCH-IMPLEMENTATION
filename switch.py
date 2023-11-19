#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


class currentSTPState:
    def __init__(self, priority, root_switch, root_bridge, root_path_cost, current_switch):
        self.priority = priority
        self.root_switch = root_switch
        self.root_bridge = root_bridge
        self.root_path_cost = root_path_cost
        self.current_switch = current_switch

    def __str__(self):
        return "priority: " + str(self.priority) + "\nroot_switch: " + str(self.root_switch) + "\nroot_bridge: " + str(self.root_bridge) + "\nroot_path_cost: " + str(self.root_path_cost)

    def getPrio(self):
        return self.priority

    def setPriority(self, priority):
        self.priority = priority

    def getRootSwitch(self):
        return self.root_switch

    def setRootSwitch(self, root_switch):
        self.root_switch = root_switch

    def getRootBridge(self):
        return self.root_bridge

    def setRootBridge(self, root_bridge):
        self.root_bridge = root_bridge

    def getRootPathCost(self):
        return self.root_path_cost

    def setRootPathCost(self, root_path_cost):
        self.root_path_cost = root_path_cost

    def getCurrentSwitch(self):
        return self.current_switch

    def setCurrentSwitch(self, current_switch):
        self.current_switch = current_switch


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


def read_switch_config(switch_id, switch_config, switch_priorities):
    # reads the switch configuration file from ./configs/switchX.config where X is the switch number
    # structure of the file:
    # PRIORITY
    # INTERFACE_NAME [VLAN_ID / TRUNK]

    # open the file for the switch id
    file = open("./configs/switch" + str(switch_id) + ".cfg", "r")

    # read the priority on the first line
    priority = file.readline()

    # store the priority in the switch_priorities
    switch_priorities[switch_id] = priority

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


def forward(src_mac, dst_mac, vlan_id, interface, ethertype,
            mac_cam_table, switch_config, data, length,
            interfaces, stp_states, switch_id):
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
        if switch_config[mac_cam_table[dst_mac]] == "T":
            # if the interface is not blocking
            if stp_states[(switch_id, mac_cam_table[dst_mac])] != 0:
                send_to_link(mac_cam_table[dst_mac], data_copy, length_copy)

        elif vlan_id == int(switch_config[mac_cam_table[dst_mac]]):
            send_to_link(mac_cam_table[dst_mac], data_copy, length_copy)

        # else if we receive from access and send to access
        elif vlan_id == -1 and int(switch_config[mac_cam_table[dst_mac]]) == int(switch_config[interface]):
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
                if switch_config[i] == "T":
                    # if the interface is not blocking
                    if stp_states[(switch_id, i)] != 0:
                        send_to_link(i, data_copy, length_copy)

                elif vlan_id == int(switch_config[i]):
                    send_to_link(i, data_copy, length_copy)

                # else if we receive from access and send to access
                elif vlan_id == -1 and int(switch_config[i]) == int(switch_config[interface]):
                    send_to_link(i, data_copy, length_copy)


def modify_packet(vlan_id, dst_interface, switch_config, data, length,
                  interfaces, ethertype, src_interface):
    if dst_interface in interfaces:
        # if the packet is coming from access port
        if vlan_id == -1:
            # if the interface is trunk type
            if switch_config[dst_interface] == "T":
                # add the vlan tag to the packet
                data = data[0:12] + \
                    create_vlan_tag(
                        int(switch_config[src_interface])) + data[12:]

                # increase the length of the packet
                length += 4

        # if the packet is coming from trunk port
        else:
            # if the interface is access type then remove the vlan tag
            if switch_config[dst_interface] != "T":
                # remove the vlan tag from the packet
                data = data[0:12] + data[16:]

                # decrease the length of the packet
                length -= 4

    return data, length


def create_bpdu(root_bridge_id_p, sender_bridge_id, sender_path_cost_p):
    # creates bpdu packet with structure
    # DST_MAC|SRC_MAC|LLC_LENGTH|LLC_HEADER|BPDU_HEADER|BPDU_CONFIG
    # LLC_LENGTH is the total length of the LLC_HEADER and BPDU_HEADER
    # LLC_HEADER has the following structure
    # DSAP (Destination Service Access Point)|SSAP (Source Service Access Point)|Control
    # DSAP and SSAP will be 0x42 and control will be 0x03.

    # dsc_mac is 01:80:C2:00:00:00 multicast address
    dst_mac = b'\x01\x80\xc2\x00\x00\x00'

    # src_mac is the sender mac address computed with get_switch_mac
    src_mac = get_switch_mac()

    # llc_length is 52
    llc_length = 52

    # llc_header is 0x42 0x42 0x03
    llc_header = b'\x42\x42\x03'

    # bpdu_header is protocol id, protocol version id, bpdu type
    # protocol id is 0x00 0x00
    # protocol version id is 0x00
    # bpdu type is 0x00
    bpdu_header = b'\x00\x00\x00\x00'

    # bpdu config has the structure:
    #   uint8_t  flags;
    #   uint8_t  root_bridge_id[8];
    #   uint32_t root_path_cost;
    #   uint8_t  bridge_id[8];
    #   uint16_t port_id;
    #   uint16_t message_age;
    #   uint16_t max_age;
    #   uint16_t hello_time;
    #   uint16_t forward_delay;
    # set flags to 0
    flags = 0

    # copy bytes from root_bridge_id_p to root_bridge_id
    root_bridge_id = root_bridge_id_p.to_bytes(8, byteorder='big')

    # copy bytes from sender_path_cost_p to root_path_cost
    root_path_cost = sender_path_cost_p.to_bytes(4, byteorder='big')

    # copy bytes from sender_bridge_id_p to bridge_id
    bridge_id = sender_bridge_id.to_bytes(8, byteorder='big')

    # set port_id to 0
    port_id = 0

    # set message_age to 0
    message_age = 0

    # set max_age to 20
    max_age = 20

    # set hello_time to 2
    hello_time = 2

    # set forward_delay to 15
    forward_delay = 15

    # create the bpdu config
    bpdu_config = flags.to_bytes(1, byteorder='big') + root_bridge_id + \
        root_path_cost + bridge_id + port_id.to_bytes(2, byteorder='big') + \
        message_age.to_bytes(2, byteorder='big') + \
        max_age.to_bytes(2, byteorder='big') + \
        hello_time.to_bytes(2, byteorder='big') + \
        forward_delay.to_bytes(2, byteorder='big')

    return dst_mac + src_mac + llc_length.to_bytes(2, byteorder='big') + \
        llc_header + bpdu_header + bpdu_config


def send_bpdu(interface, root_bridge_id, sender_bridge_id, sender_path_cost):
    # create the bpdu packet
    bpdu = create_bpdu(root_bridge_id, sender_bridge_id, sender_path_cost)

    # send the bpdu packet to the interface
    send_to_link(interface, bpdu, len(bpdu))


def send_bpdu_every_second(interfaces, switch_config, switch_priorities, currentSTPState):
    # every 1 second, if we are root switch, sends out BPDUs
    while True:
        print("comparing YES YESY YES", int(
            switch_priorities[currentSTPState.getCurrentSwitch()]), " with ", currentSTPState.getRootBridge())
        if int(switch_priorities[currentSTPState.getCurrentSwitch()]) == currentSTPState.getRootBridge():
            # send out BPDUs
            for i in interfaces:
                if switch_config[i] == "T":
                    # Set sender path cost to 0
                    sender_path_cost = 0

                    print("Sending BPDU from SWITCH ", currentSTPState.getCurrentSwitch(),
                          " on interface ", i)
                    # Send BPDU
                    send_bpdu(i, currentSTPState.getRootBridge(),
                              int(switch_priorities[currentSTPState.getCurrentSwitch()]), sender_path_cost)

        # wait 1 second
        time.sleep(1)


def prepare_stp(switch_id, interfaces, stp_states, switch_config,
                switch_priorities):
    # prepare the stp states
    # for each trunk port on the switch, set it as blocking
    for i in interfaces:
        if switch_config[i] == "T":
            stp_states[(switch_id, i)] = 0

    # set own bridge id as the priority from config
    own_bridge_id = int(switch_priorities[switch_id])
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    # if port becomes root bridge, set it as designated
    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            if switch_config[i] == "T":
                stp_states[(switch_id, i)] = 1

    return own_bridge_id, root_bridge_id, root_path_cost, stp_states


def parse_bpdu(bpdu, currentState, interface, interfaces,
               stp_states, switch_config, own_bridge_id, port):
    # Parse the BPDU
    root_bridge_id = int.from_bytes(bpdu[22:30], byteorder='big')
    sender_path_cost = int.from_bytes(bpdu[30:34], byteorder='big')
    sender_bridge_id = int.from_bytes(bpdu[34:42], byteorder='big')

    print("Parsed Root Bridge ID: " + str(root_bridge_id))
    print("Parsed Sender Path Cost: " + str(sender_path_cost))
    print("Parsed Sender Bridge ID: " + str(sender_bridge_id))
    print("Global root Bridge ID: " + str(currentState.getRootBridge()))
    print("Global root Path Cost: " + str(currentState.getRootPathCost()))
    print("Port ID: " + str(port))

    print("Comparing ROOT_BID " + str(root_bridge_id) +
          " and GLOBAL_ROOT_BID " + str(currentState.getRootBridge()))

    print("Comparing SENDER_BID " + str(sender_bridge_id) +
          " and OWN_BID " + str(currentState.getRootBridge()))

    root_port = -1

    if root_bridge_id < currentState.getRootBridge():
        currentState.setRootBridge(root_bridge_id)
        # Add 10 to the path cost because we have 100 Mbps links
        currentState.setRootPathCost(sender_path_cost + 10)
        root_port = port

        # if we were the Root Bridge:
        # set all interfaces not to hosts to BLOCKING except the root port
        if own_bridge_id == currentState.getRootBridge():
            for i in interfaces:
                if switch_config[i] == "T":
                    if i != root_port:
                        print("Setting " + str(i) + " to BLOCKING")
                        stp_states[(currentState.getCurrentSwitch(), i)] = 0

        # if root_port state is BLOCKING:
        # Set root_port state to LISTENING
        if stp_states[(currentState.getCurrentSwitch(), root_port)] == 0:
            stp_states[(currentState.getCurrentSwitch(), root_port)] = 1

        # Update and forward this BPDU to all other trunk ports with:
        # sender_bridge_ID = own_bridge_ID
        # sender_path_cost = root_path_cost
        for i in interfaces:
            if switch_config[i] == "T":
                if i != port:
                    print("Sending BPDU on " + str(i))
                    sender_bridge_id = own_bridge_id
                    send_bpdu(i, root_bridge_id,
                              sender_bridge_id, currentState.getRootPathCost())

    # else if BPDU.root_bridge_ID == root_bridge_ID
    elif root_bridge_id == currentState.getRootBridge():
        if port == root_port and sender_path_cost + 10 < currentState.getRootPathCost():
            currentState.setRootPathCost(sender_path_cost + 10)
        elif port != root_port:
            if sender_path_cost > currentState.getRootPathCost():
                if stp_states[(currentState.getCurrentSwitch(), port)] != 1:
                    stp_states[(currentState.getCurrentSwitch(), port)] = 1

    elif sender_bridge_id == currentState.getRootBridge():
        # set the port to BLOCKING
        print("Setting " + str(port) + " to BLOCKING")
        stp_states[(currentState.getCurrentSwitch(), port)] = 0

    # Set as designated if we are the root bridge
    if own_bridge_id == currentState.getRootBridge():
        for i in interfaces:
            if switch_config[i] == "T":
                if stp_states[(currentState.getCurrentSwitch(), i)] != 1:
                    stp_states[(currentState.getCurrentSwitch(), i)] = 1

    return currentState, stp_states


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    # print the switch id
    print("SWITCH ID: " + str(switch_id))

    # make mac CAM table for the switch
    mac_cam_table = {}

    # create the sitch configuration dictionary
    switch_config = {}

    # create the switch priorities dictionary
    switch_priorities = {}

    # create the stp data struct containing pairs {(switch_id, interface) -> state}
    # state are BLOCKING = 0, DESIGNATED = 1, LISTENING = 2
    stp_states = {}

    # read the switch configuration file
    read_switch_config(switch_id, switch_config, switch_priorities)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Prepare the STP algorithm
    own_bridge_id, root_bridge_id, root_path_cost, stp_states = prepare_stp(
        switch_id, interfaces, stp_states, switch_config, switch_priorities)

    currentState = currentSTPState(
        own_bridge_id, switch_id, root_bridge_id, root_path_cost, switch_id)

    # Print the prepared STP results
    print("[INFO] Prepared STP results")
    print("own_bridge_id: " + str(own_bridge_id))
    print("root_bridge_id: " + str(root_bridge_id))
    print("root_path_cost: " + str(root_path_cost))

    # print the stp states
    print("[INFO] STP states")
    for (switch_id, interface), state in stp_states.items():
        print("switch_id: " + str(switch_id) + " interface: " +
              str(interface) + " state: " + str(state))

    # start the thread that sends out BPDUs every second
    t = threading.Thread(target=send_bpdu_every_second, args=(
        interfaces, switch_config, switch_priorities, currentState))
    t.start()

    # print the switch configuration in human readable format
    print("[INFO] Switch configuration")
    for interface_name, vlan_id_or_trunk_type in switch_config.items():
        print(get_interface_name(interface_name) + " :: " + "interface number: " +
              str(interface_name) +
              " vlan id or trunk type: " + str(vlan_id_or_trunk_type))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

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
        print()

        # if the frame is a BPDU, parse it and update the STP state
        if dest_mac == "01:80:c2:00:00:00":
            currentState, stp_states = parse_bpdu(data, currentState, interface, interfaces,
                                                  stp_states, switch_config, own_bridge_id, interface)
            # print ports statuses
            print("[INFO] PORT states")
            for (switch_id, interface), state in stp_states.items():
                print("switch_id: " + str(switch_id) + " interface: " +
                      str(interface) + " state: " + str(state))

            # else if the frame is a data frame, forward it
        else:
            forward(src_mac, dest_mac, vlan_id, interface,
                    ethertype, mac_cam_table, switch_config,
                    data, length, interfaces, stp_states, switch_id)


if __name__ == "__main__":
    main()
