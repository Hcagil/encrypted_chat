# encrypted_chat

## 1. Public Key Certification. 
  Each user should generate an RSA public-private key pair once and register the server with her username and public key. Server signs this keyand creates a certificate, stores the certificate and also sends a copy to the user. When user receives the certificate, she verifies that the certificate is correct and the public key is correctly received by the server. 
## 2. Handshaking.
  When user1 wants to communicate with user2, she sends a hello message together with her public key certificate to user2. User2 sends back a random number (nonce) together with his public key certificate. User1 encrypts the nonce with her private key and sends back to user2. User2 verifies the nonce and send an acknowledgement to user1. Then user1 generates a master secret and sends it to user2 in a secure way.
## 3. Key Generation. 
  Both user1 and user2 generates necessary keys for encryption and Message Authentication Code (MAC), as well as initialization vector(s) (IV). These keys and IV(s) should be derived from master secret.
## 4. Message Encryption. 
  All the messages between pairs must be encrypted using a block cipher. You may use any standard block cipher you like, but all the messages must be encrypted using CBC mode (with the IV generated in the previous step).
## 5. Integrity Check.
  Every message going over the network should have a MAC, to enable detection of a malicious attacker tampering with the messages en route. You can either use hashing (HMAC) or block cipher (CMAC) to generate MAC.
## 6. Resistance to Replay Attacks.
  Even after you secure all the transmitted messages with encryption and MACs, there is still an obvious replay attack possible. Trudy can capture a message and repeatedly send this message. You should prevent the attacker from replaying any message.
