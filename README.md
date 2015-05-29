# EncryptedChat
Chat/server programs with RSA and AES encryption!
The programs uses SSLSockets to send communicate between each other. All messages are encrypted with a 256-bit AES key, which is encrypted and exchanged upon connection with the server using 2048 bit RSA public/private keys.
There server is CLI only, while the client also has a GUI, please note that on Microsoft Windows the CLI (but not the GUI) version of the client lacks utf-8 support.
