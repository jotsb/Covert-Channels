Covert-Channels
===============

###Objective:
The objective of this assignment was to become familiar with covert channels and to design a covert channel using the TCP / IP protocol suite. This first part of this assignment consists of analyzing the “covert_tcp.c” program designed by Craig Rowland. The program designed by Craig Rowland uses three basic techniques to covertly embed data into IP and TCP headers. The three techniques are manipulation of the IP Identification field, Initial sequence number field and the TCP acknowledge sequence number field “Bounce”. The second part of this assignment consists of using the base code provided by Craig Rowland and the modifying it to suit a method of sending data covertly other than what is already being done in the code. <br />

###Assignment Details:
Our assignment has been modified to use the IP Identification field, TCP sequence number field, the TCP acknowledgment field, IP header type of service field and TCP urgent pointer field for a direct transfer from a compromised client machinethe listening server. In a “Bounce” transfer the TCP sequence number field and TCP acknowledgment number field are used to send data. In the bounce transfer using sequence and acknowledgment fields, the client encodes the data into the TCP sequence field and the server listening for the data receives the data encoded into the acknowledgment fieldsequence number + 1.

