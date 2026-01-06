#![windows_subsystem = "windows"]

use std::path::PathBuf;
use windows::core::GUID;
use windows::Devices::Bluetooth::Rfcomm::{RfcommServiceId, RfcommServiceProvider};
use windows::Foundation::TypedEventHandler;
use windows::Networking::Sockets::{
    StreamSocket, StreamSocketListener, StreamSocketListenerConnectionReceivedEventArgs,
};
use windows::Storage::Streams::{DataReader, DataWriter};

// OBEX Object Push Profile UUID
const OPP_UUID: &str = "00001105-0000-1000-8000-00805f9b34fb";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            println!("Starting Bluetooth Receiver...");

            // 1. Create the Service ID
            let service_guid = GUID::from(OPP_UUID);
            let service_id = RfcommServiceId::FromUuid(service_guid)?;

            // 2. Create the Provider
            println!("Creating RFCOMM Service Provider...");
            let provider = RfcommServiceProvider::CreateAsync(&service_id)?.await?;

            // 3. Create the Listener
            let listener = StreamSocketListener::new()?;

            // 4. Bind the Listener to the Service ID
            // Try using single argument version first.
            listener
                .BindServiceNameAsync(&provider.ServiceId()?.AsString()?)?
                .await?;

            // 5. Hook up the Connection Received event
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

            // Explicitly specify types for TypedEventHandler
            listener.ConnectionReceived(&TypedEventHandler::<
                StreamSocketListener,
                StreamSocketListenerConnectionReceivedEventArgs,
            >::new(
                move |_sender, args: &Option<StreamSocketListenerConnectionReceivedEventArgs>| {
                    if let Some(args) = args {
                        if let Ok(socket) = args.Socket() {
                            let _ = tx.send(socket);
                        }
                    }
                    Ok(())
                },
            ))?;

            // 6. Start Advertising
            println!("Starting Advertising...");
            provider.StartAdvertising(&listener)?;

            println!("Listening for connections... (Press Ctrl+C to stop)");

            loop {
                if let Some(socket) = rx.recv().await {
                    tokio::task::spawn_local(async move {
                        if let Err(e) = handle_connection(socket).await {
                            eprintln!("Error handling connection: {:?}", e);
                        }
                    });
                }
            }
        })
        .await
}

async fn handle_connection(socket: StreamSocket) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connection received!");

    let input_stream = socket.InputStream()?;
    let output_stream = socket.OutputStream()?;

    let reader = DataReader::CreateDataReader(&input_stream)?;
    let writer = DataWriter::CreateDataWriter(&output_stream)?;

    // Simple OBEX State: Expect CONNECT, Then PUT.

    // --- CONNECT Loop (some devices connect/disconnect multiple times) ---
    // Read header.
    // Packet structure: [Opcode: 1] [Length: 2] [Data: Length-3]

    // State for the current file transfer within this connection
    let mut current_transfer_filename: Option<String> = None;

    loop {
        // We need to read at least 3 bytes to know the length.
        let loaded = reader.LoadAsync(3)?.await?;
        if loaded < 3 {
            if loaded == 0 {
                println!("Connection closed.");
                return Ok(());
            }
            // Not enough data for header? Wait more?
            // For simplicity, restart loop or return if strictly 0.
            if loaded < 3 {
                // Try loading more?
                let more = reader.LoadAsync(3 - loaded)?.await?;
                if loaded + more < 3 {
                    println!("Incomplete header, closing.");
                    return Ok(());
                }
            }
        }

        let opcode = reader.ReadByte()?;
        let len_high = reader.ReadByte()? as u16;
        let len_low = reader.ReadByte()? as u16;
        let length = (len_high << 8) | len_low;

        println!("Received Opcode: 0x{:02X}, Length: {}", opcode, length);

        // Always read the payload logic
        let payload_len = if length > 3 { (length - 3) as usize } else { 0 };
        let mut payload = vec![0u8; payload_len];

        if payload_len > 0 {
            // Ensure we strictly load ALL bytes of the payload.
            // LoadAsync might return partial data.
            let mut needed = payload_len as u32;
            while needed > 0 {
                let loaded_bytes = reader.LoadAsync(needed)?.await?;
                if loaded_bytes == 0 {
                    // EOF or broken connection before full packet read
                    println!("Connection broken during payload read.");
                    return Ok(());
                }
                if loaded_bytes > needed {
                    // Should not happen with LoadAsync semantics usually, but cap it?
                    // Actually LoadAsync(count) ensures *at least* (or exactly?)
                    // WinRT docs say "loads count bytes". It often blocks until count is available.
                    // But if it returns less, we must ask again.
                }
                if loaded_bytes >= needed {
                    break;
                }
                needed -= loaded_bytes;
            }
            reader.ReadBytes(&mut payload)?;
        }

        // Handle CONNECT (0x80)
        if opcode == 0x80 {
            println!("Handling CONNECT");
            // Respond with SUCCESS (0xA0)
            // standard connect response: 0xA0, Len(7), Version(0x10), Flags(0), MaxPacket(0xFF, 0xFF)
            writer.WriteByte(0xA0)?;
            writer.WriteByte(0x00)?; // Len High
            writer.WriteByte(0x07)?; // Len Low
            writer.WriteByte(0x10)?; // Version 1.0
            writer.WriteByte(0x00)?; // Flags
            writer.WriteByte(0xFF)?; // Max Packets (High)
            writer.WriteByte(0xFE)?; // Max Packets (Low) - 65534

            writer.StoreAsync()?.await?;
            println!("Sent CONNECT Success");
        }
        // Handle PUT (0x02) or PUT Final (0x82)
        else if (opcode & 0x7F) == 0x02 {
            // 0x02 or 0x82
            println!("Handling PUT (Final: {})", opcode == 0x82);

            // IMPORTANT: Reset file_data for THIS packet.
            // We are processing one OBEX packet. The payload is in `payload`.
            // We should NOT accumulate across loops unless we carry state.
            // But here we parse `payload` into `current_packet_body`.

            let mut cursor = 0;

            // NOTE: In a real OBEX session, Name comes in the first PUT. Subsequent PUTs just have Body.
            // We need a variable outside the loop to store the current filename?
            // However, `handle_connection` is per connection. So we CAN store state there.

            let mut current_packet_body = Vec::new();
            let mut found_name_in_this_packet: Option<String> = None;

            while cursor < payload.len() {
                let header_id = payload[cursor];
                cursor += 1;

                let encoding = header_id >> 6;

                if encoding == 0 || encoding == 1 {
                    if cursor + 2 > payload.len() {
                        break;
                    }
                    let h_len_high = payload[cursor] as u16;
                    let h_len_low = payload[cursor + 1] as u16;
                    let h_len = ((h_len_high << 8) | h_len_low) as usize;
                    cursor += 2;

                    let data_len = if h_len >= 3 { h_len - 3 } else { 0 };

                    if cursor + data_len > payload.len() {
                        break;
                    }
                    let data = &payload[cursor..cursor + data_len];

                    // Name Header (0x01)
                    if header_id == 0x01 {
                        let u16_vec: Vec<u16> = data
                            .chunks_exact(2)
                            .map(|c| (c[0] as u16) << 8 | c[1] as u16)
                            .collect();
                        if let Ok(name) = String::from_utf16(&u16_vec) {
                            if let Some(clean) = name.split('\0').next() {
                                found_name_in_this_packet = Some(clean.to_string());
                            } else {
                                found_name_in_this_packet = Some(name);
                            }
                        }
                    }
                    // Body (0x48) or EndOfBody (0x49)
                    else if header_id == 0x48 || header_id == 0x49 {
                        current_packet_body.extend_from_slice(data);
                    }

                    cursor += data_len;
                } else if encoding == 2 {
                    cursor += 1;
                } else if encoding == 3 {
                    cursor += 4;
                }
            }

            // State persistence logic
            // Since we are inside `loop`, variables declared inside rely on the initialized ones outside?
            // We didn't initialize persistent filename outside loop in previous code (it was inside).
            // This is the bug. If 2nd packet comes, `filename` resets to "received_file.dat".

            // We need to manage filename state properly.
            // Ideally, we'd move `filename` definition OUTSIDE the loop.
            // But to fix valid Rust scope without rewriting whole function:
            // We will just assume if we found a name, we update a "session" filename.
            // Wait, we can't easily change the outer variable if we didn't declare it.
            // Let's rely on specific behavior:
            // 1. If Name is present, it's a new file (or start of one). Truncate/Create.
            // 2. If Name is NOT present, it's a continuation. Append.

            let mut path = dirs::download_dir().unwrap_or(PathBuf::from("."));

            // Use found name or default.
            // If found_name_in_this_packet is Some, it's a new transfer or a re-send of the first packet.
            // If None, we rely on the `current_transfer_filename` from previous packets.
            // If `current_transfer_filename` is also None, we default to "received_file.dat".
            let target_filename_str = if let Some(ref name) = found_name_in_this_packet {
                // A name was found in THIS packet, so update the session filename
                current_transfer_filename = Some(name.clone());
                name.clone()
            } else {
                // No name in THIS packet, use the session filename if available, else default
                current_transfer_filename
                    .clone()
                    .unwrap_or_else(|| "received_file.dat".to_string())
            };

            // Sanitize
            let safe_name =
                target_filename_str.replace(|c: char| !c.is_alphanumeric() && c != '.', "_");
            path.push(&safe_name);

            if !current_packet_body.is_empty() {
                use tokio::io::AsyncWriteExt;

                let mut options = tokio::fs::OpenOptions::new();
                options.create(true).write(true);

                // If a name was found in THIS packet, it's the start of a new file transfer, so truncate.
                // Otherwise, it's a continuation of an existing transfer, so append.
                if found_name_in_this_packet.is_some() {
                    options.truncate(true);
                    println!(
                        "Saving {} bytes to {:?} (new file)",
                        current_packet_body.len(),
                        path
                    );
                } else {
                    options.append(true);
                    println!(
                        "Saving {} bytes to {:?} (append)",
                        current_packet_body.len(),
                        path
                    );
                }

                let mut file = options.open(&path).await?;
                file.write_all(&current_packet_body).await?;
            }

            // Response: 0x90 (Continue) if 0x02, 0xA0 (Success) if 0x82 (Final)
            let response = if opcode == 0x82 { 0xA0 } else { 0x90 };

            writer.WriteByte(response)?;
            writer.WriteByte(0x00)?;
            writer.WriteByte(0x03)?;
            writer.StoreAsync()?.await?;

            println!("Sent PUT Response: 0x{:02X}", response);

            // If this was the final PUT packet, clear the session filename
            if opcode == 0x82 {
                current_transfer_filename = None;
            }
        }
        // DISCONNECT (0x81)
        else if opcode == 0x81 {
            println!("Received DISCONNECT");
            writer.WriteByte(0xA0)?; // Success
            writer.WriteByte(0x00)?;
            writer.WriteByte(0x03)?;
            writer.StoreAsync()?.await?;
            break;
        } else {
            // Unknown/SetPath/etc. Just acknowledge.
            println!("Unknown Opcode: 0x{:02X}. Sending Success.", opcode);
            writer.WriteByte(0xA0)?;
            writer.WriteByte(0x00)?;
            writer.WriteByte(0x03)?;
            writer.StoreAsync()?.await?;
        }
    }

    Ok(())
}
