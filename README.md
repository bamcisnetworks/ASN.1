# ASN.1

## Introduction
This module provides cmdlets to work with and parse ASN.1 formatted data structures. There are numerous libraries that can help parse
ASN.1, BER, DER, and CER formatted content, but I had not seen any done in PowerShell. This module is extremely useful to help parse
RSA private keys from .PEM files and create RSACrytpoServiceProvider objects entirely in PowerShell without any external library dependencies.

## Revision History

### 1.0.0.4
Fixed endianess issues with byte arrays and conversions.

### 1.0.0.3
Fixed handling for context specific tag elements. 

### 1.0.0.2
Adjusted handling for bit strings and unused bit space indicators.

### 1.0.0.1
Updated integer data handling.

### 1.0.0.0
Initial Release.