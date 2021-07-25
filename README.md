# Mix Server Implementation

This is a simple implementation of a mix server.

## Basic explanation

A mix server is a way to hide meta data so 2 parties could be able to communicate with each other without a MitM (3rd party) being able to know those 2 parties are communicating with each other.

### How it works: 

Side A wants to send a message to side B.

Side A then encrypts their message with side B's public key (RSA).

Side A then adds side B's IP address and port.

Side A encrypts that with the mix server's public key (RSA) and sends that to the server.

The mix server then decrypts all messages and sends them in batches (in this implementation, once every 60 seconds), that way, making it much harder for a MitM to know that side A sent a message to side B.

## How to run

Edit the file "messages1.txt" and put your message in that format:

> < message > < servers numbers separated by commas > < desired round to be sent > < password > < salt > < dest IP > < dest port >

For example:

> ddd 3,2,1 0 password password 127.0.0.1 5000

Edit the ips.txt with the IPs and ports of the server so the first line is server 1, the second line is server 2 and so on.

You can also create new private keys and public keys for the servers but the repo comes with 3 private keys and public keys included for 3 servers.

Running the sender:

    python3 sender.py <number of the messages file, for messages1.txt enter 1>

Running the server:

    python3 mix.py <number of the server>

Running the receiver:

    python3 receiver.py <password> <salt> <port>

