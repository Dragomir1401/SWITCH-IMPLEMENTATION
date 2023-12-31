#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


class currentSTPState:
    def __init__(self, priority, root_switch, root_bridge, root_path_cost, current_switch, current_is_root_bridge):
        self.priority = priority
        self.root_switch = root_switch
        self.root_bridge = root_bridge
        self.root_path_cost = root_path_cost
        self.current_switch = current_switch
        self.current_is_root_bridge = current_is_root_bridge

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

    def getCurrentIsRootBridge(self):
        return self.current_is_root_bridge

    def setCurrentIsRootBridge(self, current_is_root_bridge):
        self.current_is_root_bridge = current_is_root_bridge


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    # Dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
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
    # Vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)


def read_switch_config(switch_id, switch_config, switch_priorities):
    # Reads the switch configuration file from ./configs/switchX.config where X is the switch number
    # Structure of the file:
    # PRIORITY
    # INTERFACE_NAME [VLAN_ID / TRUNK]

    # Open the file for the switch id
    file = open("./configs/switch" + str(switch_id) + ".cfg", "r")

    # Read the priority on the first line
    priority = file.readline()

    # Store the priority in the switch_priorities
    switch_priorities[switch_id] = priority

    # Define increasing interface id
    interface_id = 0

    # Parse every line with the interface name and vlan id or trunk type and store it in the switch_config
    for line in file:
        # Pass first line
        if line == priority:
            continue

        # Split the line into the interface name and vlan id or trunk type
        interface_name, vlan_id_or_trunk_type = line.split()

        # Add the interface name and vlan id or trunk type to the switch_config
        switch_config[interface_id] = vlan_id_or_trunk_type

        # Increase the interface id
        interface_id += 1


def forward(src_mac, dst_mac, vlan_id, interface, ethertype,
            mac_cam_table, switch_config, data, length,
            interfaces, stp_states, switch_id):
    # Add the src_mac to the mac_cam_table if it is not already there
    if src_mac not in mac_cam_table:
        mac_cam_table[src_mac] = interface

    # If the type of packet is unicast, then forward the packet to the interface
    # That is in the mac_cam_table
    if dst_mac in mac_cam_table:
        # Make a copy of the packet
        data_copy = data
        length_copy = length

        # Modify packet if necessary
        data_copy, length_copy = modify_packet(
            vlan_id, mac_cam_table[dst_mac], switch_config, data_copy, length_copy, interfaces, ethertype, interface)

        # Send the packet to the interface that is in the mac_cam_table if it is trunk type or same vlan
        if switch_config[mac_cam_table[dst_mac]] == "T":
            # If the interface is not blocking
            if stp_states[(switch_id, mac_cam_table[dst_mac])] != 0:
                send_to_link(mac_cam_table[dst_mac], data_copy, length_copy)

        elif vlan_id == int(switch_config[mac_cam_table[dst_mac]]):
            send_to_link(mac_cam_table[dst_mac], data_copy, length_copy)

        # Else if we receive from access and send to access
        elif vlan_id == -1 and int(switch_config[mac_cam_table[dst_mac]]) == int(switch_config[interface]):
            send_to_link(mac_cam_table[dst_mac], data_copy, length_copy)

    else:
        # If the type of packet is broadcast, then forward the packet to all
        # Interfaces except the one that received the packet
        for i in interfaces:
            if i != interface:
                # Make a copy of the packet
                data_copy = data
                length_copy = length

                # Modify packet if necessary
                data_copy, length_copy = modify_packet(vlan_id, i, switch_config,
                                                       data_copy, length_copy, interfaces, ethertype, interface)

                # Send the packet to the interface if it is trunk type or same vlan
                if switch_config[i] == "T":
                    # If the interface is not blocking
                    if stp_states[(switch_id, i)] != 0:
                        send_to_link(i, data_copy, length_copy)

                elif vlan_id == int(switch_config[i]):
                    send_to_link(i, data_copy, length_copy)

                # Else if we receive from access and send to access
                elif vlan_id == -1 and int(switch_config[i]) == int(switch_config[interface]):
                    send_to_link(i, data_copy, length_copy)


def modify_packet(vlan_id, dst_interface, switch_config, data, length,
                  interfaces, ethertype, src_interface):
    if dst_interface in interfaces:
        # If the packet is coming from access port
        if vlan_id == -1:
            # If the interface is trunk type
            if switch_config[dst_interface] == "T":
                # Add the vlan tag to the packet
                data = data[0:12] + \
                    create_vlan_tag(
                        int(switch_config[src_interface])) + data[12:]

                # Increase the length of the packet
                length += 4

        # If the packet is coming from trunk port
        else:
            # If the interface is access type then remove the vlan tag
            if switch_config[dst_interface] != "T":
                # Remove the vlan tag from the packet
                data = data[0:12] + data[16:]

                # Decrease the length of the packet
                length -= 4

    return data, length


def create_bpdu(root_bridge_id_p, sender_bridge_id, sender_path_cost_p):
    # Creates bpdu packet with structure
    # DST_MAC|SRC_MAC|LLC_LENGTH|LLC_HEADER|BPDU_HEADER|BPDU_CONFIG
    # LLC_LENGTH is the total length of the LLC_HEADER and BPDU_HEADER
    # LLC_HEADER has the following structure
    # DSAP (Destination Service Access Point)|SSAP (Source Service Access Point)|Control
    # DSAP and SSAP will be 0x42 and control will be 0x03.

    # Dsc_mac is 01:80:C2:00:00:00 multicast address
    dst_mac = b'\x01\x80\xc2\x00\x00\x00'

    # Src_mac is the sender mac address computed with get_switch_mac
    src_mac = get_switch_mac()

    # llc_length is 52
    llc_length = 52

    # llc_header is 0x42 0x42 0x03
    llc_header = b'\x42\x42\x03'

    # Bpdu_header is protocol id, protocol version id, bpdu type
    # Protocol id is 0x00 0x00
    # Protocol version id is 0x00
    # Bpdu type is 0x00
    bpdu_header = b'\x00\x00\x00\x00'

    # Bpdu config has the structure:
    #   uint8_t  flags;
    #   uint8_t  root_bridge_id[8];
    #   uint32_t root_path_cost;
    #   uint8_t  bridge_id[8];
    #   uint16_t port_id;
    #   uint16_t message_age;
    #   uint16_t max_age;
    #   uint16_t hello_time;
    #   uint16_t forward_delay;
    # Set flags to 0
    flags = 0

    # Copy bytes from root_bridge_id_p to root_bridge_id
    root_bridge_id = root_bridge_id_p.to_bytes(8, byteorder='big')

    # Copy bytes from sender_path_cost_p to root_path_cost
    root_path_cost = sender_path_cost_p.to_bytes(4, byteorder='big')

    # Copy bytes from sender_bridge_id_p to bridge_id
    bridge_id = sender_bridge_id.to_bytes(8, byteorder='big')

    # Set port_id to 0
    port_id = 0

    # Set message_age to 0
    message_age = 0

    # Set max_age to 20
    max_age = 20

    # Set hello_time to 2
    hello_time = 2

    # Set forward_delay to 15
    forward_delay = 15

    # Create the bpdu config
    bpdu_config = flags.to_bytes(1, byteorder='big') + root_bridge_id + \
        root_path_cost + bridge_id + port_id.to_bytes(2, byteorder='big') + \
        message_age.to_bytes(2, byteorder='big') + \
        max_age.to_bytes(2, byteorder='big') + \
        hello_time.to_bytes(2, byteorder='big') + \
        forward_delay.to_bytes(2, byteorder='big')

    return dst_mac + src_mac + llc_length.to_bytes(2, byteorder='big') + \
        llc_header + bpdu_header + bpdu_config


def send_bpdu(interface, root_bridge_id, sender_bridge_id, sender_path_cost):
    # Create the bpdu packet
    bpdu = create_bpdu(root_bridge_id, sender_bridge_id, sender_path_cost)

    # Send the bpdu packet to the interface
    send_to_link(interface, bpdu, len(bpdu))


def send_bpdu_every_second(interfaces, switch_config, switch_priorities, currentSTPState):
    # Every 1 second, if we are root switch, sends out BPDUs
    while True:
        if int(switch_priorities[currentSTPState.getCurrentSwitch()]) == currentSTPState.getRootBridge():
            # Send out BPDUs
            for i in interfaces:
                if switch_config[i] == "T":
                    # Set sender path cost to 0
                    sender_path_cost = 0

                    # Send BPDU
                    send_bpdu(i, currentSTPState.getRootBridge(),
                              int(switch_priorities[currentSTPState.getCurrentSwitch()]), sender_path_cost)

        # Wait 1 second
        time.sleep(1)


def prepare_stp(switch_id, interfaces, stp_states, switch_config,
                switch_priorities):
    # For each trunk port on the switch, set it as blocking
    for i in interfaces:
        if switch_config[i] == "T":
            stp_states[(switch_id, i)] = 0

    # Set own bridge id as the priority from config
    own_bridge_id = int(switch_priorities[switch_id])
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    # If port becomes root bridge, set it as designated
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

    # Set root_port to default value
    root_port = -1

    if root_bridge_id < currentState.getRootBridge():
        currentState.setRootBridge(root_bridge_id)
        # Add 10 to the path cost because we have 100 Mbps links
        currentState.setRootPathCost(sender_path_cost + 10)
        root_port = port

        # if we were the Root Bridge:
        # set all interfaces not to hosts to BLOCKING except the root port
        if currentState.getCurrentIsRootBridge():
            for i in interfaces:
                if switch_config[i] == "T":
                    if i != root_port:
                        stp_states[(currentState.getCurrentSwitch(), i)] = 0
            currentState.setCurrentIsRootBridge(False)

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
                    sender_bridge_id = own_bridge_id
                    send_bpdu(i, root_bridge_id,
                              sender_bridge_id, currentState.getRootPathCost())

    elif root_bridge_id == currentState.getRootBridge():
        if port == root_port and sender_path_cost + 10 < currentState.getRootPathCost():
            currentState.setRootPathCost(sender_path_cost + 10)
        # Check if port has to be set to designated
        elif port != root_port:
            if sender_path_cost > currentState.getRootPathCost():
                if stp_states[(currentState.getCurrentSwitch(), port)] != 1:
                    stp_states[(currentState.getCurrentSwitch(), port)] = 1

    elif sender_bridge_id == currentState.getRootBridge():
        # If loop detected, set port to BLOCKING
        stp_states[(currentState.getCurrentSwitch(), port)] = 0

    # Set all ports on root bridge to designated
    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            if switch_config[i] == "T":
                if stp_states[(currentState.getCurrentSwitch(), i)] != 1:
                    stp_states[(currentState.getCurrentSwitch(), i)] = 1

    return currentState, stp_states


def main():
    # Init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    # Print the switch id
    print("SWITCH ID: " + str(switch_id))

    # Make mac CAM table for the switch
    mac_cam_table = {}

    # Create the sitch configuration dictionary
    switch_config = {}

    # Create the switch priorities dictionary
    switch_priorities = {}

    # Create the stp data struct containing pairs {(switch_id, interface) -> state}
    # State are BLOCKING = 0, DESIGNATED = 1, LISTENING = 2
    stp_states = {}

    # Read the switch configuration file
    read_switch_config(switch_id, switch_config, switch_priorities)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # Prepare the STP algorithm
    own_bridge_id, root_bridge_id, root_path_cost, stp_states = prepare_stp(
        switch_id, interfaces, stp_states, switch_config, switch_priorities)

    # Create the current state object
    currentState = currentSTPState(
        own_bridge_id, switch_id, root_bridge_id, root_path_cost, switch_id, True)

    # Start the thread that sends out BPDUs every second
    t = threading.Thread(target=send_bpdu_every_second, args=(
        interfaces, switch_config, switch_priorities, currentState))
    t.start()

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

        # If the frame is a BPDU, parse it and update the STP state
        if dest_mac == "01:80:c2:00:00:00":
            currentState, stp_states = parse_bpdu(data, currentState, interface, interfaces,
                                                  stp_states, switch_config, own_bridge_id, interface)
            # Print ports statuses
            print("[INFO] PORT states")
            for (switch_id, interface), state in stp_states.items():
                print("switch_id: " + str(switch_id) + " interface: " +
                      str(interface) + " state: " + str(state))

        # Else if the frame is a data frame, forward it
        else:
            forward(src_mac, dest_mac, vlan_id, interface,
                    ethertype, mac_cam_table, switch_config,
                    data, length, interfaces, stp_states, switch_id)


if __name__ == "__main__":
    main()
