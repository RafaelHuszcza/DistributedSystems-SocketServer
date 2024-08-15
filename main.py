import socket
import threading
import hashlib
import base64
import struct
import json
from message_handlers import handle_room_join, handle_text_message, handle_client_leave
import os
from dotenv import load_dotenv
# Carregar variáveis de ambiente do arquivo .env
load_dotenv()
# Constants
MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Global dictionaries to store the clients and rooms
clients_connected = {}
clientId_to_authorId = {}
rooms = {}
lock = threading.Lock()

def create_websocket_accept_key(key):
    """Create a Sec-WebSocket-Accept key for the WebSocket handshake."""
    sha1 = hashlib.sha1((key + MAGIC_STRING).encode('utf-8')).digest()
    accept_key = base64.b64encode(sha1).decode('utf-8')
    return accept_key

def handle_client(client_socket, client_address):
    """Handles the WebSocket connection with a client."""
    client_id = client_address[1]  # Using port number as a unique client ID
    print (f"Client {client_id} connected", flush=True)
    with lock:
        clients_connected[client_id] = {"socket": client_socket, "rooms": []}

    try:
        # Step 1: Perform WebSocket handshake
        print("Try handshake", flush=True)
        request = client_socket.recv(1024).decode('utf-8')
        headers = parse_headers(request)
        
        websocket_key = headers.get("Sec-WebSocket-Key")
        if not websocket_key:
            print("Invalid WebSocket request", flush=True)
            client_socket.close()
            return
        print("The Key",websocket_key, flush=True)
        accept_key = create_websocket_accept_key(websocket_key)
        handshake_response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key}\r\n\r\n"
        )
        client_socket.sendall(handshake_response.encode('utf-8'))
        
        # Step 2: Receive and handle WebSocket frames
        while True:
            print(f"Waiting for message from client {client_id}", flush=True)
            frame = client_socket.recv(2048)
            if not frame:
                print(f"Connection closed by client {client_id}", flush=True)
                break
            opcode, payload = decode_websocket_frame(frame)
            print(f"Received frame with opcode {opcode}", flush=True)

            if opcode == 8:  # Close frame
                print(f"Connection closed by client {client_id}",flush=True)
                allCo = decode_websocket_frame_all(frame)
                print("All",allCo, flush=True)

                # Inform all clients that a user left
                with lock:
                    if client_id in clients_connected:
                        for room in clients_connected[client_id]["rooms"]:
                            if room in rooms:
                                rooms[room].remove(client_id)
                                if not rooms[room]:  # Remove room if empty
                                    del rooms[room]
                                authorId = clientId_to_authorId.get(client_id)
                                members, leaving_user = handle_client_leave(authorId, room)
                                for client in rooms.get(room, []):
                                    send_websocket_message(clients_connected[client]["socket"], leaving_user)
                                    send_websocket_message(clients_connected[client]["socket"], members)
                        del clients_connected[client_id]
                break

            if opcode == 1:  # Text frame
                message = payload.decode('utf-8')
                message_serialized = json.loads(message)
                print(f"Received message from client {client_id}: {message_serialized}", flush=True)
                if message_serialized["type"] == 'join':
                    room_id = message_serialized["roomId"]
                    author_id = message_serialized["authorId"]
                   
                    with lock:
                        if room_id not in rooms:
                            rooms[room_id] = []
                        
                        rooms[room_id].append(client_id)
                        clients_connected[client_id]["rooms"].append(room_id)
                        clientId_to_authorId[client_id] = author_id
                    members, new_join = handle_room_join(message_serialized)
                    
                    with lock:
                        
                        for client in rooms.get(room_id, []):
                          
                            send_websocket_message(clients_connected[client]["socket"], members)
                            send_websocket_message(clients_connected[client]["socket"], new_join)
                elif message_serialized["type"] == 'message':
                    new_message = handle_text_message(message_serialized)

                    with lock:
                        for client in rooms.get(message_serialized["roomId"], []):
                            send_websocket_message(clients_connected[client]["socket"], new_message)

                elif message_serialized["type"] == 'leave':
                    room_id = message_serialized["roomId"]
                    author_id = message_serialized["authorId"]

                    with lock:
                        if room_id in rooms:
                            rooms[room_id].remove(client_id)
                            leaving_user = handle_client_leave(author_id, room_id)
                            for client in rooms.get(room_id, []):
                                send_websocket_message(clients_connected[client]["socket"], leaving_user)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up client and rooms on disconnect
        with lock:
            if client_id in clients_connected:
                for room in clients_connected[client_id]["rooms"]:
                    if room in rooms:
                        rooms[room].remove(client_id)
                        if not rooms[room]:  # Remove room if empty
                            del rooms[room]
                del clients_connected[client_id]
        client_socket.close()

def parse_headers(request):
    """Parses the HTTP headers from the WebSocket handshake request."""
    headers = {}
    lines = request.splitlines()
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value
    return headers

def decode_websocket_frame_all(frame):
    """Decodes a WebSocket frame and returns detailed information about the frame."""
    if not frame:
        return None, None, None, None, None

    byte1, byte2 = frame[:2]
    fin = byte1 & 0b10000000  # Final fragment flag
    rsv1 = byte1 & 0b01000000  # RSV1
    rsv2 = byte1 & 0b00100000  # RSV2
    rsv3 = byte1 & 0b00010000  # RSV3
    opcode = byte1 & 0b00001111  # Opcode

    is_masked = byte2 & 0b10000000  # Mask bit
    payload_length = byte2 & 0b01111111  # Payload length

    mask = None
    payload = None
    mask_start = 2

    if payload_length == 126:
        payload_length = struct.unpack(">H", frame[2:4])[0]
        mask_start = 4
    elif payload_length == 127:
        payload_length = struct.unpack(">Q", frame[2:10])[0]
        mask_start = 10

    if is_masked:
        mask = frame[mask_start:mask_start + 4]
        payload_start = mask_start + 4
        payload = bytearray(frame[payload_start:payload_start + payload_length])
        for i in range(payload_length):
            payload[i] ^= mask[i % 4]
    else:
        payload = frame[mask_start:mask_start + payload_length]

    return {
        "fin": fin,
        "rsv1": rsv1,
        "rsv2": rsv2,
        "rsv3": rsv3,
        "opcode": opcode,
        "masked": is_masked,
        "payload_length": payload_length,
        "mask": mask,
        "payload": payload
    }
def decode_websocket_frame(frame):
    """Decodes a WebSocket frame and returns the opcode and payload."""
    byte1, byte2 = frame[:2]
    opcode = byte1 & 0b00001111
    is_masked = byte2 & 0b10000000
    payload_length = byte2 & 0b01111111

    if payload_length == 126:
        payload_length = struct.unpack(">H", frame[2:4])[0]
        mask_start = 4
    elif payload_length == 127:
        payload_length = struct.unpack(">Q", frame[2:10])[0]
        mask_start = 10
    else:
        mask_start = 2

    if is_masked:
        mask = frame[mask_start:mask_start + 4]
        payload_start = mask_start + 4
        payload = bytearray(frame[payload_start:payload_start + payload_length])
        for i in range(payload_length):
            payload[i] ^= mask[i % 4]
    else:
        payload = frame[mask_start:mask_start + payload_length]

    return opcode, payload

def send_websocket_message(client_socket, message):
    """Encodes and sends a WebSocket message."""
    message = message.encode('utf-8')
    frame = bytearray()
    frame.append(0b10000001)  # Text frame (FIN + opcode)
    
    if len(message) <= 125:
        frame.append(len(message))
    elif len(message) <= 65535:
        frame.append(126)
        frame.extend(struct.pack(">H", len(message)))
    else:
        frame.append(127)
        frame.extend(struct.pack(">Q", len(message)))

    frame.extend(message)
    client_socket.sendall(frame)

def run_server(host='0.0.0.0', port=8080):
    """Runs the WebSocket server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"WebSocket server running on wss://{host}:{port}", flush=True)

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address}", flush=True)
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

    except KeyboardInterrupt:
        print("Shutting down the server...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    # host = os.getenv('SERVER_HOST', '0.0.0.0')
    host = '0.0.0.0'
    port = int(os.getenv('SERVER_PORT', 8080))
    run_server(host,port)
