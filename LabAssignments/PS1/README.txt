Problem Set 1: Internetworking
Each student should submit his own report: NO TEAM work.

Late submissions will not be accepted.

1. Internetworking
Describe in detail all the steps that your internet browser goes through when you click on a web page such as http://www.northeastern.edu/. You should describe which protocols are invoked (e.g., TCP, ARP, DNS, ethernet), their parameters (e.g., port numbers, addresses), network entities (e.g., DNS server, default gateway/router) and the network stack structure.

Provide screen dumps (or packets listing) from a packet sniffer such as wireshark to confirm your description.

Hints: clear your machine's arp table before clicking on the web page link, use information from ipconfig/ifconfig, route, etc.

2. Sockets Programming: Design and Implementation of a Basic Chat Application
The goal of this part is to refresh your knowledge of socket programming, practice it with the Python programming language, and prepare you for the final project. Please carefully read all the instructions. Also, carefully design, implement, comment, and test your system.

Design and implement a client-server chat application in Python. All communications should use UDP sockets. When started, the server should listen on a UDP port specified as an argument to the program (-sp port). When started, a client sends a SIGN-IN message to the server including a USERNAME. The IP address and port of the server should be given as arguments to the client program (-sip server-ip -sp port). On receiving the SIGN-IN message from a client, the server will record important information about the client for enabling future communications between multiple clients (e.g., username, IP address, port). Note that using the argparse python module will make the command line parsing cleaner and easier.

The client program should support two user commands:

  list
  send USERNAME MESSAGE
the 'list' command should display all the users currently signed into the system. The 'send' command sends the user USERNAME a message, MESSAGE.

Additional Constraints: the messages should be directly sent to the clients and not transit through the server. This means that when executing the send command, the client should first retrieve the IP address and port of the destination USERNAME and use this information to directly send the message.

In order to make your design scalable, your design should support a way to allow the server to systematically distinguish between received messages/commands. There are at least three types of packets SIGN-IN, LIST, and MESSAGE. Make sure that you are able to distinguish between them in an elegant and scalable way. You might want to consider python's pickle serialization, json, or bytearrays to achieve this.

A sample run of your application must work as follows:

server$ python ChatServer.py -sp 9090 runs the server on port 9090
Server Initialized... Server is left running
user1$ python ChatClient.py -u Alice -sip server-ip -sp 9090 runs the client and signs in with username Alice.
+> Prompt message from user
+> list Requests list of signed in users at server
<– Signed In Users: Bob, Carole Displays list of signed in users
+> send Carole Hello this is Alice. Sends Carole "Hello this is Alice"
<– <From IP:PORT:Carole>: Hi Alice! How are you The client also displays received messages.
+>
Note the following:

The messages do not need to be authenticated, confirmed nor encrypted.
There is no limit to the number of clients the server supports.
There is no limit to the message size.