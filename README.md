# TLS-Attacker Workflow Explorer

[![Java Version](https://img.shields.io/badge/Java-1.8%2B-blue.svg)](https://www.oracle.com/java/technologies/javase-downloads.html)
[![TLS-Attacker](https://img.shields.io/badge/TLS--Attacker-7.1.1-green.svg)](https://github.com/tls-attacker/TLS-Attacker)
[![License](https://img.shields.io/badge/License-Apache%204.0.0-orange.svg)](LICENSE)

A Java project for exploring, testing, and understanding TLS exchanges using the TLS-Attacker framework.

## 📖 Table of Contents

- [Introduction](#introduction)
- [Architecture](#architecture)
- [Key Concepts](#key-concepts)


## Introduction

### What is this project?

This project is a practical exploration of the TLS-Attacker framework. It allows you to programmatically build, send, and analyze TLS exchanges in Java.

In other words: instead of using a browser or a classic TLS client, you code the messages you want to send to the server, in any order you want, and observe exactly what happens.

> 💡 **Simple Analogy**
>
> Imagine TLS is a secure handshake protocol between two people.
>
> This project gives you complete control over every step of that handshake:
> you decide what to say, when to say it, and you read exactly what the other person responds.


## Architecture

### Overview

The project is organized into 5 distinct packages, each with a clear and well-defined responsibility:

| Package | Main Class | Responsibility |
|---------|------------|----------------|
| `config` | `TlsClientConfig` | TLS settings: host, port, versions, cipher suites |
| `workflow` | `TlsWorkflowBuilder` | Construction of TLS message sequences |
| `executer` | `TlsWorkflowExecutor` | Workflow execution over the network |
| `handler` | `TlsMessageHandler` | Result analysis and inspection |
| `serverlauncher` | `OpenSSLServerLauncher` | Automatic startup of a test TLS server |

### Execution Flow



```markdown

1. **App.main()** → Entry point, registers BouncyCastle
   ↓
2. **OpenSSLServerLauncher** → Generates certificate and starts TLS server
   ↓
3. **TlsClientConfig** → Creates TLS configuration (host, port, ciphers)
   ↓
4. **TlsWorkflowBuilder** → Builds the sequence of messages to send
   ↓
5. **TlsWorkflowExecutor** → Executes the workflow on the real network
   ↓
6. **TlsMessageHandler** → Analyzes sent and received messages
   ↓
7. **OpenSSLServerLauncher** → Properly shuts down the server (finally block)
```


## Key Concepts

### WorkflowTrace

A `WorkflowTrace` is simply an ordered list of TLS actions. Each action can be:

| Action Type | Description |
|-------------|-------------|
| `SendAction` | Sends one or more TLS messages to the server |
| `ReceiveAction` | Waits for and reads specific messages from the server |
| `GenericReceiveAction` | Receives any message without filtering |


### BouncyCastle 

TLS-Attacker uses BouncyCastle as its cryptography provider. It's an open-source Java library that implements all necessary cryptographic algorithms (RSA, AES, SHA, ECDHE, etc.).

> ⚠️ **Important Note**
>
> BouncyCastle must be registered **MANUALLY** before any TLS-Attacker calls:
>
> ```java
> Security.insertProviderAt(new BouncyCastleProvider(), 1);
> ```
>
> Without this line, the program throws a `BouncyCastleNotLoadedException`.


