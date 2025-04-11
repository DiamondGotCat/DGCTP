
![DGHTP_1024](https://github.com/user-attachments/assets/9a99ea6d-e389-46d0-a492-6f661cf5de6a)

# DGHTP  
DiamondGotCat Hypertext Transfer Protocol

## Infomation
- Name: DGHTP
- Alias: DGHTTP (Add One "T")
- Type: Protocol
- Usage: Hypertext Transfer Protocol
- Usage-Example: File Hosting, Web Site Hosting, etc.


## URL-Scheme

### Syntax
`{name}{is-always-encrypted ? "s" : ""}{is-selected-metdot-on-scheme ? "-" : ""}{selected-metdot}{is-selected-version-on-scheme ? "-" : ""}{selected-version}`

**examples**
- `dghtp-b-a://`
- `dghtps-get://`
- `dghttp-d-c://`
- `dghttp-post-b-b://`

**name**
- `dghtp`
- `dghttp`

**selected-metdot**
- `get`
- `post`

**selected-version**
Please see `URL-Scheme's Version Syntax` Section.

### URL-Scheme's Version Syntax
- `0`: `a`
- `1`: `b`
- `2`: `c`
- `3`: `d`
- `4`: `e`
- `5`: `f`
- `6`: `g`
- `7`: `h`
- `8`: `i`
- `9`: `j`
- `.`: `-`

Example: `1.0` -> `b-a`

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
- 📡 Works over any TCP connection
- 🧰 Easy to implement, extend, and debug
