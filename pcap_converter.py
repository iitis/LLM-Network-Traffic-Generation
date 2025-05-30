import struct
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Data
from scapy.layers.zigbee import ZigbeeAppDataPayload, ZigbeeClusterLibrary, ZigbeeNWK, ZigbeeNWKCommandPayload, LinkStatusEntry
import json
import sys

class ZigbeePacketGenerator:
    def __init__(self, timestamp):
        """
        Initialize the ZigbeePacketGenerator with a timestamp.
        :param timestamp: The base timestamp for the packets.
        """
        self.timestamp = timestamp
        self.seqnum_mac = 0
        self.seqnum_nwk = 0
        self.counter_aps = 0

    def generate_packet(self, packet_info, timediff, pan_id, destination_addr, source_addr):
        """
        Generate a Zigbee packet based on the provided packet_info and other parameters.
        """
        def get_seqnum_zcl(packet_info):
            """
            Get the sequence number for ZCL commands.
            If the packet_info indicates a ZCL command, return the sequence number.
            Otherwise, return 0.
            """
            if "ZCL: " in packet_info and "Seq: " in packet_info:
                seqnum_zcl = int(packet_info.split("Seq: ")[1].split(",")[0])
                return seqnum_zcl
            return 0

        if "ZCL: Read Attributes Response" in packet_info:
            seqnum_zcl = get_seqnum_zcl(packet_info)
            return self._zcl_read_attributes_response(
                timediff=timediff,
                pan_id=pan_id,
                destination_addr=destination_addr,
                source_addr=source_addr,
                seqnum_mac=self._next_seqnum_mac(),
                seqnum_nwk=self._next_seqnum_nwk(),
                seqnum_zcl=seqnum_zcl,
                counter_aps=self._next_counter_aps()
            )
        elif "ZCL: Read Attributes" in packet_info:
            seqnum_zcl = get_seqnum_zcl(packet_info)
            return self._zcl_read_attributes(
                timediff=timediff,
                pan_id=pan_id,
                destination_addr=destination_addr,
                source_addr=source_addr,
                seqnum_mac=self._next_seqnum_mac(),
                seqnum_nwk=self._next_seqnum_nwk(),
                seqnum_zcl=seqnum_zcl,
                counter_aps=self._next_counter_aps()
            )
        elif "ZCL Groups: Get Group Membership Response" in packet_info:
            seqnum_zcl = get_seqnum_zcl(packet_info)
            return self._zcl_get_group_membership_response(
                timediff=timediff,
                pan_id=pan_id,
                destination_addr=destination_addr,
                source_addr=source_addr,
                seqnum_mac=self._next_seqnum_mac(),
                seqnum_nwk=self._next_seqnum_nwk(),
                seqnum_zcl=seqnum_zcl,
                counter_aps=self._next_counter_aps()
            )
        elif "ZCL Groups: Get Group Membership" in packet_info:
            seqnum_zcl = get_seqnum_zcl(packet_info)
            return self._zcl_get_group_membership(
                timediff=timediff,
                pan_id=pan_id,
                destination_addr=destination_addr,
                source_addr=source_addr,
                seqnum_mac=self._next_seqnum_mac(),
                seqnum_nwk=self._next_seqnum_nwk(),
                seqnum_zcl=seqnum_zcl,
                counter_aps=self._next_counter_aps()
            )
        elif "ZCL Scenes: Get Scene Membership Response" in packet_info:
            seqnum_zcl = get_seqnum_zcl(packet_info)
            return self._zcl_get_scene_membership_response(
                timediff=timediff,
                pan_id=pan_id,
                destination_addr=destination_addr,
                source_addr=source_addr,
                seqnum_mac=self._next_seqnum_mac(),
                seqnum_nwk=self._next_seqnum_nwk(),
                seqnum_zcl=seqnum_zcl,
                counter_aps=self._next_counter_aps()
            )
        elif "ZCL Scenes: Get Scene Membership" in packet_info:
            seqnum_zcl = get_seqnum_zcl(packet_info)
            return self._zcl_get_scene_membership(
                timediff=timediff,
                pan_id=pan_id,
                destination_addr=destination_addr,
                source_addr=source_addr,
                seqnum_mac=self._next_seqnum_mac(),
                seqnum_nwk=self._next_seqnum_nwk(),
                seqnum_zcl=seqnum_zcl,
                counter_aps=self._next_counter_aps()
            )
        elif "Link Status" in packet_info:
            return self._link_status(
                timediff=timediff,
                pan_id=pan_id,
                source_addr=source_addr,
                seqnum_mac=self._next_seqnum_mac(),
                seqnum_nwk=self._next_seqnum_nwk()
            )
        else:
            raise ValueError(f"Unknown packet type: {packet_info}")

    def _zcl_read_attributes(self, timediff, pan_id, destination_addr, source_addr, seqnum_mac, seqnum_nwk, seqnum_zcl, counter_aps):
        """
        Create a Zigbee data packet for ZCL: Read Attributes
        """
        pkt = (
            # Frame Control Field (FCF) for a IEEE 802.15.4 data frame
            Dot15d4(
                fcf_frametype=1,            # Frame Type: Data Frame
                fcf_security=0,             # Security Enabled: False
                fcf_pending=0,              # Frame Pending: False
                fcf_ackreq=1,               # Acknowledgment Request: True
                fcf_panidcompress=1,        # PAN ID Compression: True
                fcf_destaddrmode=2,         # Destination Addressing Mode: 16-bit short address
                fcf_framever=0,             # Frame Version: 0
                fcf_srcaddrmode=2,          # Source Addressing Mode: 16-bit short address
                seqnum=seqnum_mac           # Sequence Number for MAC layer
            ) /
            # Data Payload for IEEE 802.15.4 data frame
            Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=destination_addr,
                src_panid=pan_id,
                src_addr=source_addr) /
            # Zigbee NWK Layer
            ZigbeeNWK(
                frametype=0,                    # Frame Type: Data
                proto_version=2,                # Protocol Version: 2
                discover_route=1,               # Discover Route: True
                # flags=['security'],             # Security Flag: True - commented out for simplicity
                destination=destination_addr,   # Destination Address
                source=source_addr,             # Source Address
                radius=30,                      # Radius for the packet
                seqnum=seqnum_nwk,              # Sequence Number for NWK layer
            ) /
            # Zigbee Application Support Layer Data
            ZigbeeAppDataPayload(
                frame_control=0x00,         # Frame Control Field: Data
                delivery_mode=0,            # Delivery Mode: Unicast
                cluster=0xfc03,             # Cluster: Manufacturer Specific (0xfc03)
                profile=0x0104,             # Profile: Home Automation
                src_endpoint=64,            # Source Endpoint: 11
                dst_endpoint=11,            # Destination Endpoint: 64
                counter=counter_aps,        # Counter
            ) /
            # Zigbee Cluster Library Command
            ZigbeeClusterLibrary(
                zcl_frametype=0,                    # Frame Type: Profile-wide
                manufacturer_specific=1,            # Manufacturer Specific: True
                direction=0,                        # Direction: Client to Server
                disable_default_response=0,         # Disable Default Response: False
                manufacturer_code=0x100b,           # Manufacturer Code: Philips (0x100b)
                transaction_sequence=seqnum_zcl,    # Sequence Number
                command_identifier=0x00             # Command: Read Attributes
            )
        )
        pkt.time = self.timestamp + timediff
        return pkt

    def _zcl_read_attributes_response(self, timediff, pan_id, destination_addr, source_addr, seqnum_mac, seqnum_nwk, seqnum_zcl, counter_aps):
        """
        Create a Zigbee data packet for ZCL: Read Attributes Response
        """
        pkt = (
            # Frame Control Field (FCF) for a IEEE 802.15.4 data frame
            Dot15d4(
                fcf_frametype=1,            # Frame Type: Data Frame
                fcf_security=0,             # Security Enabled: False
                fcf_pending=0,              # Frame Pending: False
                fcf_ackreq=1,               # Acknowledgment Request: True
                fcf_panidcompress=1,        # PAN ID Compression: True
                fcf_destaddrmode=2,         # Destination Addressing Mode: 16-bit short address
                fcf_framever=0,             # Frame Version: 0
                fcf_srcaddrmode=2,          # Source Addressing Mode: 16-bit short address
                seqnum=seqnum_mac           # Sequence Number for MAC layer
            ) /
            # Data Payload for IEEE 802.15.4 data frame
            Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=destination_addr,
                src_panid=pan_id,
                src_addr=source_addr) /
            # Zigbee NWK Layer
            ZigbeeNWK(
                frametype=0,                    # Frame Type: Data
                proto_version=2,                # Protocol Version: 2
                discover_route=1,               # Discover Route: True
                # flags=['security'],             # Security Flag: True - commented out for simplicity
                destination=destination_addr,   # Destination Address
                source=source_addr,             # Source Address
                radius=30,                      # Radius for the packet
                seqnum=seqnum_nwk,              # Sequence Number for NWK layer
            ) /
            # Zigbee Application Support Layer Data
            ZigbeeAppDataPayload(
                frame_control=0x00,         # Frame Control Field: Data
                delivery_mode=0,            # Delivery Mode: Unicast
                cluster=0xfc03,             # Cluster: Manufacturer Specific (0xfc03)
                profile=0x0104,             # Profile: Home Automation
                src_endpoint=11,            # Source Endpoint: 11
                dst_endpoint=64,            # Destination Endpoint: 64
                counter=counter_aps,        # Counter
            ) /
            # Zigbee Cluster Library Command
            ZigbeeClusterLibrary(
                zcl_frametype=0,                    # Frame Type: Profile-wide
                manufacturer_specific=1,            # Manufacturer Specific: True
                direction=1,                        # Direction: Server to Client
                disable_default_response=1,         # Disable Default Response: True
                manufacturer_code=0x100b,           # Manufacturer Code: Philips (0x100b)
                transaction_sequence=seqnum_zcl,    # Sequence Number
                command_identifier=0x01             # Command: Read Attributes Response
            )
        )
        pkt.time = self.timestamp + timediff
        return pkt
    
    def _zcl_get_group_membership(self, timediff, pan_id, destination_addr, source_addr, seqnum_mac, seqnum_nwk, seqnum_zcl, counter_aps):
        """
        # Create a Zigbee data packet for ZCL Groups: Get Group Membership
        """

        # Create a payload for ZCL Groups: Get Group Membership
        group_list = []
        group_count = len(group_list)
        zcl_payload = struct.pack(
            "<B",
            group_count
        ) + b"".join(struct.pack("<H", gid) for gid in group_list)

        pkt = (
            # Frame Control Field (FCF) for a IEEE 802.15.4 data frame
            Dot15d4(
                fcf_frametype=1,            # Frame Type: Data Frame
                fcf_security=0,             # Security Enabled: False
                fcf_pending=0,              # Frame Pending: False
                fcf_ackreq=1,               # Acknowledgment Request: True
                fcf_panidcompress=1,        # PAN ID Compression: True
                fcf_destaddrmode=2,         # Destination Addressing Mode: 16-bit short address
                fcf_framever=0,             # Frame Version: 0
                fcf_srcaddrmode=2,          # Source Addressing Mode: 16-bit short address
                seqnum=seqnum_mac           # Sequence Number for MAC layer
            ) /
            # Data Payload for IEEE 802.15.4 data frame
            Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=destination_addr,
                src_panid=pan_id,
                src_addr=source_addr) /
            # Zigbee NWK Layer
            ZigbeeNWK(
                frametype=0,                    # Frame Type: Data
                proto_version=2,                # Protocol Version: 2
                discover_route=1,               # Discover Route: True
                # flags=['security'],             # Security Flag: True - commented out for simplicity
                destination=destination_addr,   # Destination Address
                source=source_addr,             # Source Address
                radius=30,                      # Radius for the packet
                seqnum=seqnum_nwk,              # Sequence Number for NWK layer
            ) /
            # Zigbee Application Support Layer Data
            ZigbeeAppDataPayload(
                frame_control=0x00,         # Frame Control Field: Data
                delivery_mode=0,            # Delivery Mode: Unicast
                cluster=0x0004,             # Cluster: Groups (0x0004)
                profile=0x0104,             # Profile: Home Automation
                src_endpoint=64,            # Source Endpoint: 11
                dst_endpoint=11,            # Destination Endpoint: 64
                counter=counter_aps,        # Counter
            ) /
            # Zigbee Cluster Library Command
            ZigbeeClusterLibrary(
                zcl_frametype=1,                    # Frame Type: Cluster-specific
                manufacturer_specific=0,            # Manufacturer Specific: False
                direction=0,                        # Direction: Client to Server
                disable_default_response=0,         # Disable Default Response: False
                transaction_sequence=seqnum_zcl,    # Sequence Number
                command_identifier=0x02             # Command: Get Group Membership Response
            )/
            Raw(load=zcl_payload)
        )
        pkt.time = self.timestamp + timediff
        return pkt

    def _zcl_get_group_membership_response(self, timediff, pan_id, destination_addr, source_addr, seqnum_mac, seqnum_nwk, seqnum_zcl, counter_aps):
        """
        # Create a Zigbee data packet for ZCL Groups: Get Group Membership Response
        """

        # Create a payload for ZCL Groups: Get Group Membership Response
        group_capacity = 21
        group_list = [0x2060, 0x2062, 0x2068, 0x2648]
        group_count = len(group_list)
        zcl_payload = struct.pack(
            "<BB", 
            group_capacity, 
            group_count
        ) + b"".join(struct.pack("<H", gid) for gid in group_list)

        pkt = (
            # Frame Control Field (FCF) for a IEEE 802.15.4 data frame
            Dot15d4(
                fcf_frametype=1,            # Frame Type: Data Frame
                fcf_security=0,             # Security Enabled: False
                fcf_pending=0,              # Frame Pending: False
                fcf_ackreq=1,               # Acknowledgment Request: True
                fcf_panidcompress=1,        # PAN ID Compression: True
                fcf_destaddrmode=2,         # Destination Addressing Mode: 16-bit short address
                fcf_framever=0,             # Frame Version: 0
                fcf_srcaddrmode=2,          # Source Addressing Mode: 16-bit short address
                seqnum=seqnum_mac           # Sequence Number for MAC layer
            ) /
            # Data Payload for IEEE 802.15.4 data frame
            Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=destination_addr,
                src_panid=pan_id,
                src_addr=source_addr) /
            # Zigbee NWK Layer
            ZigbeeNWK(
                frametype=0,                    # Frame Type: Data
                proto_version=2,                # Protocol Version: 2
                discover_route=1,               # Discover Route: True
                # flags=['security'],             # Security Flag: True - commented out for simplicity
                destination=destination_addr,   # Destination Address
                source=source_addr,             # Source Address
                radius=30,                      # Radius for the packet
                seqnum=seqnum_nwk,              # Sequence Number for NWK layer
            ) /
            # Zigbee Application Support Layer Data
            ZigbeeAppDataPayload(
                frame_control=0x00,         # Frame Control Field: Data
                delivery_mode=0,            # Delivery Mode: Unicast
                cluster=0x0004,             # Cluster: Groups (0x0004)
                profile=0x0104,             # Profile: Home Automation
                src_endpoint=11,            # Source Endpoint: 11
                dst_endpoint=64,            # Destination Endpoint: 64
                counter=counter_aps,        # Counter
            ) /
            # Zigbee Cluster Library Command
            ZigbeeClusterLibrary(
                zcl_frametype=1,                    # Frame Type: Cluster-specific
                manufacturer_specific=0,            # Manufacturer Specific: False
                direction=1,                        # Direction: Server to Client
                disable_default_response=1,         # Disable Default Response: True
                transaction_sequence=seqnum_zcl,    # Sequence Number
                command_identifier=0x02             # Command: Get Group Membership Response
            )/
            Raw(load=zcl_payload)
        )
        pkt.time = self.timestamp + timediff
        return pkt

    def _zcl_get_scene_membership(self, timediff, pan_id, destination_addr, source_addr, seqnum_mac, seqnum_nwk, seqnum_zcl, counter_aps):
        """
        Create a Zigbee data packet for ZCL Scenes: Get Scene Membership
        """
        # Create a payload for ZCL Scenes: Get Scene Membership
        group_id = 0x2060
        zcl_payload = struct.pack(
            "<H", 
            group_id
        )

        pkt = (
            # Frame Control Field (FCF) for a IEEE 802.15.4 data frame
            Dot15d4(
                fcf_frametype=1,            # Frame Type: Data Frame
                fcf_security=0,             # Security Enabled: False
                fcf_pending=0,              # Frame Pending: False
                fcf_ackreq=1,               # Acknowledgment Request: True
                fcf_panidcompress=1,        # PAN ID Compression: True
                fcf_destaddrmode=2,         # Destination Addressing Mode: 16-bit short address
                fcf_framever=0,             # Frame Version: 0
                fcf_srcaddrmode=2,          # Source Addressing Mode: 16-bit short address
                seqnum=seqnum_mac           # Sequence Number for MAC layer
            ) /
            # Data Payload for IEEE 802.15.4 data frame
            Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=destination_addr,
                src_panid=pan_id,
                src_addr=source_addr) /
            # Zigbee NWK Layer
            ZigbeeNWK(
                frametype=0,                    # Frame Type: Data
                proto_version=2,                # Protocol Version: 2
                discover_route=1,               # Discover Route: True
                # flags=['security'],             # Security Flag: True - commented out for simplicity
                destination=destination_addr,   # Destination Address
                source=source_addr,             # Source Address
                radius=30,                      # Radius for the packet
                seqnum=seqnum_nwk,              # Sequence Number for NWK layer
            ) /
            # Zigbee Application Support Layer Data
            ZigbeeAppDataPayload(
                frame_control=0x00,         # Frame Control Field: Data
                delivery_mode=0,            # Delivery Mode: Unicast
                cluster=0x0005,             # Cluster: Scenes (0x0005)
                profile=0x0104,             # Profile: Home Automation
                src_endpoint=64,            # Source Endpoint: 11
                dst_endpoint=11,            # Destination Endpoint: 64
                counter=counter_aps,        # Counter
            ) /
            # Zigbee Cluster Library Command
            ZigbeeClusterLibrary(
                zcl_frametype=1,                    # Frame Type: Cluster-specific
                manufacturer_specific=0,            # Manufacturer Specific: False
                direction=0,                        # Direction: Client to Server
                disable_default_response=0,         # Disable Default Response: False
                transaction_sequence=seqnum_zcl,    # Sequence Number
                command_identifier=0x06             # Command: Get Group Membership Response
            )/
            Raw(load=zcl_payload)
        )
        pkt.time = self.timestamp + timediff
        return pkt

    def _zcl_get_scene_membership_response(self, timediff, pan_id, destination_addr, source_addr, seqnum_mac, seqnum_nwk, seqnum_zcl, counter_aps):
        """
        Create a Zigbee data packet for ZCL Scenes: Get Scene Membership Response
        """
        # Create a payload for ZCL Scenes: Get Scene Membership Response
        scene_status = 0x00  # Status: Success
        scene_capacity = 33
        group_id = 0x2060
        scene_list = [0x01, 0x02, 0x03, 0x04, 0x05, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
        scene_count = len(scene_list)
        zcl_payload = struct.pack(
            "<BBHB", 
            scene_status,
            scene_capacity,
            group_id,
            scene_count
        ) + b"".join(struct.pack("<B", sid) for sid in scene_list)

        pkt = (
            # Frame Control Field (FCF) for a IEEE 802.15.4 data frame
            Dot15d4(
                fcf_frametype=1,            # Frame Type: Data Frame
                fcf_security=0,             # Security Enabled: False
                fcf_pending=0,              # Frame Pending: False
                fcf_ackreq=1,               # Acknowledgment Request: True
                fcf_panidcompress=1,        # PAN ID Compression: True
                fcf_destaddrmode=2,         # Destination Addressing Mode: 16-bit short address
                fcf_framever=0,             # Frame Version: 0
                fcf_srcaddrmode=2,          # Source Addressing Mode: 16-bit short address
                seqnum=seqnum_mac           # Sequence Number for MAC layer
            ) /
            # Data Payload for IEEE 802.15.4 data frame
            Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=destination_addr,
                src_panid=pan_id,
                src_addr=source_addr) /
            # Zigbee NWK Layer
            ZigbeeNWK(
                frametype=0,                    # Frame Type: Data
                proto_version=2,                # Protocol Version: 2
                discover_route=1,               # Discover Route: True
                # flags=['security'],             # Security Flag: True - commented out for simplicity
                destination=destination_addr,   # Destination Address
                source=source_addr,             # Source Address
                radius=30,                      # Radius for the packet
                seqnum=seqnum_nwk,              # Sequence Number for NWK layer
            ) /
            # Zigbee Application Support Layer Data
            ZigbeeAppDataPayload(
                frame_control=0x00,         # Frame Control Field: Data
                delivery_mode=0,            # Delivery Mode: Unicast
                cluster=0x0005,             # Cluster: Scenes (0x0005)
                profile=0x0104,             # Profile: Home Automation
                src_endpoint=11,            # Source Endpoint: 11
                dst_endpoint=64,            # Destination Endpoint: 64
                counter=counter_aps,        # Counter
            ) /
            # Zigbee Cluster Library Command
            ZigbeeClusterLibrary(
                zcl_frametype=1,                    # Frame Type: Cluster-specific
                manufacturer_specific=0,            # Manufacturer Specific: False
                direction=1,                        # Direction: Server to Client
                disable_default_response=1,         # Disable Default Response: True
                transaction_sequence=seqnum_zcl,    # Sequence Number
                command_identifier=0x06             # Command: Get Group Membership Response
            )/
            Raw(load=zcl_payload)
        )
        pkt.time = self.timestamp + timediff
        return pkt

    def _link_status(self, timediff, pan_id, source_addr, seqnum_mac, seqnum_nwk):
        """
        Create a Zigbee data packet for Link Status
        """
        pkt = (
            # Frame Control Field (FCF) for a IEEE 802.15.4 data frame
            Dot15d4(
                fcf_frametype=1,            # Frame Type: Data Frame
                fcf_security=0,             # Security Enabled: False
                fcf_pending=0,              # Frame Pending: False
                fcf_ackreq=0,               # Acknowledgment Request: False
                fcf_panidcompress=1,        # PAN ID Compression: True
                fcf_destaddrmode=2,         # Destination Addressing Mode: 16-bit short address
                fcf_framever=0,             # Frame Version: 0
                fcf_srcaddrmode=2,          # Source Addressing Mode: 16-bit short address
                seqnum=seqnum_mac           # Sequence Number for MAC layer
            ) /
            # Data Payload for IEEE 802.15.4 data frame
            Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=0xffff,
                src_panid=pan_id,
                src_addr=source_addr) /
            # Zigbee NWK Layer
            ZigbeeNWK(
                frametype=1,                    # Frame Type: Command
                proto_version=2,                # Protocol Version: 2
                discover_route=0,               # Discover Route: Suppress
                # flags=['security'],             # Security Flag: True - commented out for simplicity
                destination=0xfffc,   # Destination Address
                source=source_addr,             # Source Address
                radius=1,                       # Radius for the packet
                seqnum=seqnum_nwk,              # Sequence Number for NWK layer
            ) /
            # Zigbee Application Support Layer Data
            ZigbeeNWKCommandPayload(
                cmd_identifier=0x08,            # Command Identifier: Link Status
                last_frame=1,                   # Last Frame: True
                first_frame=1,                  # First Frame: True
                entry_count=8,                  # Entry Count: 8
                link_status_list=[
                    LinkStatusEntry(neighbor_network_address=0xa089, incoming_cost=1, outgoing_cost=5),
                    LinkStatusEntry(neighbor_network_address=0xb85c, incoming_cost=1, outgoing_cost=1),
                    LinkStatusEntry(neighbor_network_address=0xc370, incoming_cost=1, outgoing_cost=1),
                    LinkStatusEntry(neighbor_network_address=0xc9b3, incoming_cost=1, outgoing_cost=1),
                    LinkStatusEntry(neighbor_network_address=0xd7a7, incoming_cost=1, outgoing_cost=2),
                    LinkStatusEntry(neighbor_network_address=0xdfe1, incoming_cost=3, outgoing_cost=7),
                    LinkStatusEntry(neighbor_network_address=0xe46c, incoming_cost=1, outgoing_cost=1),
                    LinkStatusEntry(neighbor_network_address=0xe7f5, incoming_cost=1, outgoing_cost=1),
                ]
            )
        )
        pkt.time = self.timestamp + timediff
        return pkt

    def _next_seqnum_mac(self):
        """
        Get the next sequence number for the MAC layer.
        """
        self.seqnum_mac += 1
        if self.seqnum_mac > 255:
            self.seqnum_mac = 0
        return self.seqnum_mac
    
    def _next_seqnum_nwk(self):
        """
        Get the next sequence number for the NWK layer.
        """
        self.seqnum_nwk += 1
        if self.seqnum_nwk > 255:
            self.seqnum_nwk = 0
        return self.seqnum_nwk
    
    def _next_counter_aps(self):
        """
        Get the next counter for the APS layer.
        """
        self.counter_aps += 1
        if self.counter_aps > 255:
            self.counter_aps = 0
        return self.counter_aps


def main():
    """
    Main function to generate Zigbee packets from a JSON file.
    """
    # Load the JSON file
    if len(sys.argv) < 2:
        print("Usage: python generator.py <json_file>")
        sys.exit(1)

    json_file = sys.argv[1]

    with open(json_file, "r") as f:
        data = json.load(f)

    generator = ZigbeePacketGenerator(timestamp=1577870400.0)
    packets = []

    pan_id = 0x15de

    # Iterate through the packets in the JSON
    for packet in data["packets"]:
        timediff = float(packet["time"])
        destination_addr = int(packet["dst"], 16)
        source_addr = int(packet["src"], 16)
        packet_type = packet["info"]

        packets.append(generator.generate_packet(
            packet_info=packet_type,
            timediff=timediff,
            pan_id=pan_id,
            destination_addr=destination_addr,
            source_addr=source_addr
        ))

    output_file = json_file.rsplit(".", 1)[0] + ".pcap"
    wrpcap(output_file, packets)

if __name__ == "__main__":
    main()
