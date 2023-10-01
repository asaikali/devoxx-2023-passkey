# devoxx-2023-passkey

This repo contains the demo code from the Devoxx Beligum 2023 Deep Dive Talk

**Implementing passwordless logins using Passkey, WebAuthn protocols and Spring Authorization Server**


What if users can create an account and log into your application without ever having to enter a password. For example, a new user accesses your application from an iPhone they are able to create a new account and login using FaceId. This deep dive shows you how to use the Web Authentication Protocol, Passkeys and the Spring Security Authorization Server to implement such functionality. The Web Authentication is widely implemented in all modern browsers provides a highly secure and user-friendly on-boarding and authentication experience. Recently Google, Microsoft, and Apple introduced Passkeys as the preferred passwordless authentication technology based on FIDO and WebAuthn. In the workshop we will cover everything you need to know to understand how the WebAuthenticaiton, Passkey, FIDO2 protocols works and how to implement it using Spring Security and Spring Authorization Server. A git repo with highly commented code showing implementation will be provided. Come learn everything you need know about the exciting world of passkeys so you can add it to your existing applications or use it for your new apps. No previous background in security is required to follow along and learn. 

**Branches**

There are 4 branches in this repo corresponidng to the 4 parts of the talk.

| branch                    | Purpose         
| ------------------------- |: -------------------------------------------------------------------:| 
| 1-the-app                 | sample application with on security                                  |
| 2-passkey-basics          | sample to learn the basics of passkey                                |
| 3-authserver-basics       | sample to learn the basics of the spring authorizaton server         |
| 3-authserver-with-passkey | sample with spring authoriaztion server that has support for passkey |

