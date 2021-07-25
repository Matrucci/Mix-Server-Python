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

Edit the file "messages.txt" and put your message in that format:

> < message > < servers numbers separated by commas > < desired round to be sent > < password > < salt > < dest IP > < dest port >

For example:

> ddd 3,2,1 0 password password 127.0.0.1 5000

Run 
