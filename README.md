# Overview
This project is a secure authentication system developed in Go, leveraging passkey technology to enhance user security. The system uses RSA cryptographic keys for challenge-response authentication, ensuring robust protection against unauthorized access. The project includes user registration, challenge generation, and signature verification.

## Features
Secure User Registration: Generate and store RSA key pairs for users.
Challenge-Response Authentication: Use base64-encoded challenges and RSA signatures to authenticate users.
Scalable and High Performance: Designed for scalability to handle a large number of concurrent authentication requests.
Strong Security Protocols: Implementation of secure-by-design principles to protect against common security threats.
## Technologies Used
Programming Language: Go
Cryptography: RSA keys, SHA-256 hashing
Data Encoding: Base64
Web Framework: net/http package
Data Storage: Mock in-memory database (map)
