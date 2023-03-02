# README # Tsolaki Maria - 2017030164

The program will be excecuted follwing this steps:
1. make 
2. ./monitor -r <filename> or -i <interface name>

Function explanation:

# file_monitor #
Opens and monitors the file.

# network_monitor #
Monitors the traffic live from the given device.

# my_packet_handler #
Read packets one by one and calls the correct functions for printing and adding (if possible)
the packet in the network flow array.

# print_pack4 # # print_pack6 #
Prints the packet(if necesary) to the screen.

# manage_network_flow_ip4 # # manage_network_flow_ip6 #
Checks if the package's network flow is in the netflow array. If not this functions add it.

# signal_handler #
Handles the signals and in case of SIGINT prints the statistics and exits.

Important Note:
UDP packets can't be retransmitted.
TCP packet are retransmitted if the reciever notifies the sender that packet is not recieved correctly 
or the receiver knows that expected data has not arrived, and so notifies the send
or  the receiver knows that the data has arrived, but in a damaged condition, and indicates that to the sender.

Although, the retransmitted functionality is not implemented.

