# TCP Encrypted Chat Program

In this project, I wrote a server and client of a chat program in C. I used TCP sockets to make the connection between them. For every message you send, I made use of the OpenSSL libcrypto library to encrypt the messages being sent between users.

## Documentation

To compile files, type this in the terminal in the directory with all the files.

```
$ make
```

To run the program, you need to set it up in Linux to be able to use the OpenSSL libcrypto library.

```
./client <ip> <port>
```

```
./server <port>
```

## Client:

The client first connects to the server using TCP sockets. Once the client is connected to the server, it prompts the user for a username. After choosing an username, the client uses select() to wait for any command input from the user or any data sent from the server. You can input to the client various commands. To get a list of commands, you can input /help to get a list of commands to use. You also have the possibility of becoming an admin in the server and be able to use other commands that are only available to admins, which are protected by a password. The client also handles any kind of data being sent from the server. It can receive data that will help us get the right outputs for the requested commands, or it will receive messages that were sent from other clients.

## Server:

The server will use select() to wait for multiple client connections and then for each client connected, store them in a hash array. The server will also wait for new connections and data being sent from clients. The server can handle data being received containing different commands, and depending on the command being received, the server will do the corresponding work to execute the command.

## Commands:

The program contains a couple of commands that you can run. This is a list of what commands are available and what they do:

### /list

The list command will display a list of all the users connected to the server.
The client will send this command to the server. The server will create a list with all connected clients and send back to the client this list. When the client receives this list, it will display it.

### /msg <username> <message>

The msg command will send the message to the username
The client will send this command to the server. The server will find the username in the hash array, and send the message to the client with that username. The client that receives this message will display it.

### /all <message>

The all command will send the message to all the connected usernames except the one sending this command
The client will send this command to the server. The server will loop through all the connected clients and send to each one of them the message. Every client that receives the message will display it.

### /admin

The admin command will make the user an admin after putting the correct password.
The client will prompt the user for a password, if it is correct, it will send a request to make the user an admin to the server. The server then will set the username as an admin.

### /kick <username> (This command can only be used by admins. )

The kick command will disconnect the username from the server.
The client will send this command to the server. The server will search for this username in the hash array and send them a request to disconnect them.

### /rename <username> <new-username>

The rename command will rename the username with the new-username.
The client will send this command to the server. The server will look for the username in the hash array and then change its value of the username to the new one.

## Encryption:

The program also includes encryption for safety purposes. When clients join the chat server, they securely establish a symmetric key pair with the server. For this purpose, the server has a public/private key pair for use with RSA. To establish a symmetric key, the client randomly generates one, and then sends it to the server encrypted with the server's RSA public key. The server then decrypts it using the RSA private key. All subsequent messages are sent encrypted with this symmetric key. A random initialization vector is used in encryption to ensure unique encryptions of identical messages. It properly generates a new IV for each message.
