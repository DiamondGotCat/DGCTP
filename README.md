# DGHTP  
DiamondGotCat Hypertext Transfer Protocol

## What is this?

**DGHTP** is a next-generation communication protocol inspired by traditional HTTP/HTTPS,  
but built for **speed, security, and simplicity**.

It was designed as a lightweight, high-performance protocol based on my earlier project, **UltraDP**.  
With built-in support for **encryption**, **compression**, and **chunked transfer**, DGHTP enables  
secure and efficient data exchange — even under difficult network conditions.

## Why DGHTP?

- 🌐 Human-readable headers (e.g. `#!METHOD GET`, `#!VERSION 1.0`)
- 🔐 Built-in AES-256 encryption with PBKDF2
- 📦 Optional compression using Zstandard
- 📡 Works over any TCP connection (can even be tunneled through Tor)
- 🧰 Easy to implement, extend, and debug
