# SNAG: A Hooking Detection Engine
![Status](https://img.shields.io/badge/status-active-green) ![Language](https://img.shields.io/badge/C-Primary-blue)

## Introduction
**SNAG** is a lightweight debugging tool designed to detect function hooks in running processes. It scans **Import Address Tables (IATs)**, **Export Tables**, and performs **inline function verification** to identify potential API redirections, making it a valuable asset for reverse engineers and security analysts.

## Features
✅ Detect **Import Address Table (IAT) hooks**  
✅ Scan **Export Table** for function mismatches  
✅ Perform **inline function scans** to detect modified instructions  
✅ Cross-check **module imports** between disk and memory  
✅ ANSI-formatted output for clarity  

## How It Works
SNAG operates by:
1. **Extracting imports** from loaded DLLs within a target process.
2. **Comparing these imports to the expected function locations from disk**.
3. **Scanning export tables** to validate function addresses.
4. **Checking function prologues for unexpected redirection (JMP instructions).**
