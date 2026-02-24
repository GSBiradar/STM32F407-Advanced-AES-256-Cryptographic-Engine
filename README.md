# STM32F407-Advanced-AES-256-Cryptographic-Engine
A comprehensive, production-ready implementation of the Advanced Encryption Standard (AES-256) in Cipher Block Chaining (CBC) mode for the STM32F Discovery board. This project features a complete software-based cryptographic engine with an interactive user interface, real-time encryption/decryption capabilities, and comprehensive security features.
### ✨ Key Features

- **Full AES-256 Implementation**: Complete software implementation of AES-256 in CBC mode
- **Interactive Serial Interface**: User-friendly menu-driven system for cryptographic operations
- **Real-time Encryption/Decryption**: Process data of any size up to 256 bytes
- **PKCS#7 Padding**: Automatic padding implementation for block alignment
- **Dynamic Key/IV Management**: Change encryption keys and initialization vectors on-the-fly
- **Hex Dump Visualization**: Beautifully formatted hexadecimal output
- **Avalanche Effect Demonstration**: Visual representation of cryptographic properties
- **Verification System**: Automatic decryption verification capability
- **Multi-block Processing**: Handles data across multiple 16-byte blocks
- **Performance Metrics**: Built-in timing and validation checks

## 🎯 Project Objectives

1. Implement robust AES-256 encryption on resource-constrained embedded systems
2. Provide an educational platform for understanding block cipher operations
3. Demonstrate CBC mode properties including the avalanche effect
4. Create a reusable cryptographic framework for STM32 platforms
5. Showcase professional embedded systems programming practices


## 🔧 Technical Specifications

### Cryptographic Specifications
| Parameter | Value |
|-----------|-------|
| **Algorithm** | AES-256-CBC |
| **Key Size** | 256 bits (32 bytes) |
| **Block Size** | 128 bits (16 bytes) |
| **IV Size** | 128 bits (16 bytes) |
| **Rounds** | 14 rounds |
| **Mode** | Cipher Block Chaining (CBC) |
| **Padding** | PKCS#7 |
| **Maximum Input Size** | 256 bytes (configurable) |

### Hardware Utilization
| Resource | Usage |
|----------|-------|
| **Flash Memory** | ~12 KB |
| **RAM** | ~4 KB |
| **CPU Usage** | Variable (data-dependent) |
| **Peripherals** | USART2, GPIO |


## 📱 User Interface Features

### Main Menu System

   STM32F407 AES256-CBC Interactive    
      Enter text → Get Ciphertext    

✓ AES256 initialized with default key/IV

========================================
STM32F407 AES256-CBC Interactive Tool
========================================
1. Enter text to encrypt
2. Encrypt with current key/IV
3. Change encryption key
4. Change IV
5. Show current key and IV
6. Exit
========================================



### Data Visualization
- **Hexadecimal Dump**: 16 bytes per line with spacing
- **Continuous Hex String**: Easy copy/paste format
- **ASCII Representation**: Shows readable text
- **Padding Visualization**: Displays PKCS#7 padding bytes

## 🔄 Operational Modes

### Mode 1: Interactive Encryption
- User inputs custom text
- System applies padding automatically
- Returns formatted ciphertext
- Optional decryption verification

### Mode 2: Quick Test
- Uses predefined test vectors
- Verifies encryption pipeline
- Debug mode for troubleshooting

### Mode 3: Key Management
- Dynamic key updates
- Hexadecimal input validation
- Secure key storage in memory

### Mode 4: IV Management
- Dynamic IV updates
- Demonstrates IV importance
- Shows CBC mode properties

###UART OUTPUT


<img width="438" height="310" alt="image" src="https://github.com/user-attachments/assets/88684860-3192-4a5e-8606-d57670e8f9ba" />
<img width="268" height="140" alt="image" src="https://github.com/user-attachments/assets/d5391408-dad8-485f-a7e6-636b7eea0b3e" />

## ⚙️ Configuration Options

```c
// Configurable Parameters
#define MAX_INPUT_SIZE    256     // Maximum input buffer size
#define BLOCK_SIZE        16      // AES block size
#define AES256_KEY_SIZE   32      // Key size in bytes
#define AES256_IV_SIZE    16      // IV size in bytes
#define AES256_ROUNDS     14      // Number of encryption rounds



