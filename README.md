# Bluetooth File Receiver (Rust)

A simple Windows console application that automatically receives files transferred via Bluetooth (OBEX Push Profile), saving them to your Downloads folder.

## Prerequisites

- Windows 10 or Windows 11.
- Bluetooth Receiver/Radio enabled.
- The device (Phone) must be paired with Windows before sending files.

## Build and Run

1. Open a terminal in this directory.
2. Run:
   ```powershell
   cargo run
   ```

## Usage

1. Start the application. It will display "Listening for connections...".
2. On your phone, share a file via Bluetooth and select your PC.
3. The file should be automatically accepted and saved to `C:\Users\[You]\Downloads`.

## Troubleshooting

- **Error 0x800710DF (Device not ready)**: Ensure Bluetooth is turned on.
- **Connection Failed on Phone**: Ensure the PC is paired. Windows might block the connection if the "Bluetooth Support Service" is not running or if standard Windows file transfer is active.
