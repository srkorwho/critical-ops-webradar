from scapy.all import *
from flask import Flask, render_template_string, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import subprocess
import os
import time
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) 

conf.sniff_promisc = False
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cops-tracker-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading') 

captured_packets = []
packet_counter = 0
is_capturing = True
latest_packet = None
xor_key_global = None
bruteforce_progress = 0
is_bruteforcing = False
bruteforce_thread = None
last_decrypt_time_ms = 0

MAP_BOUNDS = { "x_min": -100, "x_max": 100, "z_min": -100, "z_max": 100 }
MAPS = [
    {
        "name": "bureau",
        "display_name": "Bureau",
        "image": "bureau.png",
        "width": 806,
        "height": 656,
        "x_min": -93.33,
        "x_max": 94.29,
        "z_min": -95.36,
        "z_max": 88.31
    },
    {
        "name": "canals",
        "display_name": "Canals",
        "image": "canals.png",
        "width": 625,
        "height": 582,
        "x_min": -88.52,
        "x_max": 80.1,
        "z_min": -96.17,
        "z_max": 92.57
    },
    {
        "name": "castello",
        "display_name": "Castello",
        "image": "castello.png",
        "width": 582,
        "height": 760,
        "x_min": -58.54,
        "x_max": 64.06,
        "z_min": -84.42,
        "z_max": 92.19
    },
    {
        "name": "grounded",
        "display_name": "Grounded",
        "image": "grounded.png",
        "width": 605,
        "height": 731,
        "x_min": -93.81,
        "x_max": 84.57,
        "z_min": -67.0,
        "z_max": 61.0
    },
    {
        "name": "legacy",
        "display_name": "Legacy",
        "image": "legacy.png",
        "width": 318,
        "height": 597,
        "x_min": -46.0,
        "x_max": 34.0,
        "z_min": -76.50,
        "z_max": 93.79
    },
    {
        "name": "plaza",
        "display_name": "Plaza",
        "image": "plaza.png",
        "width": 415,
        "height": 609,
        "x_min": -90.5,
        "x_max": 84.78,
        "z_min": -86.0,
        "z_max": 96.8
    },
    {
        "name": "port",
        "display_name": "Port",
        "image": "port.png",
        "width": 472,
        "height": 303,
        "x_min": -95.25,
        "x_max": 97.06,
        "z_min": -87.7,
        "z_max": 71.32
    },
    {
        "name": "raid",
        "display_name": "Raid",
        "image": "raid.png",
        "width": 355,
        "height": 602,
        "x_min": -93.86,
        "x_max": 91.42,
        "z_min": -95.61,
        "z_max": 87.57
    },
    {
        "name": "soar",
        "display_name": "Soar",
        "image": "soar.png",
        "width": 501,
        "height": 637,
        "x_min": -94.4,
        "x_max": 94.63,
        "z_min": -98.86,
        "z_max": 97.84
    },
    {
        "name": "village",
        "display_name": "Village",
        "image": "village.png",
        "width": 551,
        "height": 602,
        "x_min": -83.18,
        "x_max": 84.0,
        "z_min": -93.03,
        "z_max": 91.05
    }
]
current_map = MAPS[0]
latest_player_positions = []

def hex_to_real_position(x_hex, z_hex):
    try:
        x_hex = x_hex.replace("0x", "").replace(" ", "").strip()
        z_hex = z_hex.replace("0x", "").replace(" ", "").strip()
        if len(x_hex) == 4: x_hex = x_hex[2:4] + x_hex[0:2]
        if len(z_hex) == 4: z_hex = z_hex[2:4] + z_hex[0:2]
        x_value = int(x_hex, 16)
        z_value = int(z_hex, 16)
        x_norm = x_value / 65534.0
        z_norm = z_value / 65534.0
        x_real = (x_norm * (MAP_BOUNDS["x_max"] - MAP_BOUNDS["x_min"])) + MAP_BOUNDS["x_min"]
        z_real = (z_norm * (MAP_BOUNDS["z_max"] - MAP_BOUNDS["z_min"])) + MAP_BOUNDS["z_min"]
        return x_real, z_real
    except Exception as e: return None, None

def convert_to_map_pixels(x_real, z_real, map_config):
    if x_real is None or z_real is None: return None, None
    if (x_real < map_config["x_min"] or x_real > map_config["x_max"] or
        z_real < map_config["z_min"] or z_real > map_config["z_max"]):
        return None, None
    x_norm = max(0, min(1, (x_real - map_config["x_min"]) / (map_config["x_max"] - map_config["x_min"])))
    z_norm = max(0, min(1, (z_real - map_config["z_min"]) / (map_config["z_max"] - map_config["z_min"])))
    pixel_x = int(x_norm * map_config["width"])
    pixel_y = int((1 - z_norm) * map_config["height"])
    return pixel_x, pixel_y

def xorshift64_decrypt(data, seed):
    decrypted = bytearray(data)
    length = len(data)
    state = seed
    i = 0
    while i < length:
        original_state = state
        state_shifted_13 = (state << 13) & 0xFFFFFFFFFFFFFFFF
        temp_xor_1 = state ^ state_shifted_13
        temp_v10 = temp_xor_1 ^ (temp_xor_1 >> 7)
        decrypted[i] ^= ((original_state & 0xFF) ^ ((temp_xor_1 >> 7) & 0xFF))
        if i + 1 < length: decrypted[i + 1] ^= ((temp_v10 >> 8) & 0xFF)
        state_shifted_17 = (temp_v10 << 17) & 0xFFFFFFFFFFFFFFFF
        state = temp_v10 ^ state_shifted_17
        for j in range(2, 8):
            if i + j < length: decrypted[i + j] ^= ((state >> (j * 8)) & 0xFF)
        i += 8
    return bytes(decrypted)

def parse_player_positions(decrypted_hex):
    global latest_player_positions, current_map
    if len(decrypted_hex) < 12: return None
    try: player_count = int(decrypted_hex[11:12], 16)
    except: return None
    if player_count == 0:
        latest_player_positions = []
        socketio.emit('players_update', {'count': 0, 'players': []})
        return None
    player_data_start = 12
    players = []
    for i in range(player_count):
        offset = player_data_start + (i * 22)
        if offset + 22 > len(decrypted_hex): break
        player_hex = decrypted_hex[offset:offset + 22]
        x_hex = player_hex[0:4]
        z_hex = player_hex[8:12]
        x_real, z_real = hex_to_real_position(x_hex, z_hex)
        pixel_x, pixel_y = convert_to_map_pixels(x_real, z_real, current_map)
        players.append({'x_hex': x_hex, 'z_hex': z_hex, 'x_real': x_real, 'z_real': z_real, 'pixel_x': pixel_x, 'pixel_y': pixel_y})
    latest_player_positions = players
    socketio.emit('players_update', {'count': player_count, 'players': players})
    return {'count': player_count, 'players': players}

def bruteforce_with_cpp(packet_bytes):
    global xor_key_global, is_bruteforcing, bruteforce_progress
    is_bruteforcing = True 
    bruteforce_progress = 0
    
    bruteforce_exe_path = './bruteforce'
    if not os.path.exists(bruteforce_exe_path):
        print(f"[!!!] ERROR: '{bruteforce_exe_path}' not found!")
        is_bruteforcing = False
        return None
        
    packet_hex = packet_bytes.hex()
    
    print("-" * 30)
    print(f"[*] Starting C++ Bruteforce...")
    print(f"[*] Packet Hex (first 60 chars): {packet_hex[:60]}...") 
    print(f"[*] C++ Command: {bruteforce_exe_path} {packet_hex[:10]}...") 
    
    try:
        start_time = time.time() 
        process = subprocess.Popen(
            [bruteforce_exe_path, packet_hex],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        
        while True:
            line = process.stderr.readline()
            if not line: break
            print(f"[C++ STDERR] {line.strip()}") 
            if "Progress:" in line:
                try:
                    percent_str = line.split("Progress:")[1].split("%")[0].strip()
                    bruteforce_progress = float(percent_str)
                except: pass
                
        stdout_output, _ = process.communicate() 
        stdout_output = stdout_output.strip() if stdout_output else ""
        
        end_time = time.time()
        print(f"[*] C++ Process finished. Duration: {end_time - start_time:.2f} seconds") 
        print(f"[*] C++ Return Code: {process.returncode}")
        print(f"[*] C++ STDOUT (Key?): '{stdout_output}'")

        if process.returncode == 0 and stdout_output: 
            xor_key = stdout_output
            xor_key_global = xor_key
            print(f"[✓] C++ KEY FOUND: 0x{xor_key}")
            is_bruteforcing = False
            return xor_key
        else:
            print("[!] C++: No match found or an error occurred.")
            is_bruteforcing = False
            return None
            
    except Exception as e:
        print(f"[!!!] Python subprocess ERROR: {e}")
        is_bruteforcing = False
        return None

def decrypt_incoming_packet(packet_data):
    if not xor_key_global or len(packet_data) < 14: return None
    start_time = time.perf_counter()
    mystery_bytes = packet_data[10:14]
    mystery_int = int.from_bytes(mystery_bytes, 'little')
    seed = mystery_int ^ int(xor_key_global, 16)
    encrypted_payload = packet_data[14:]
    decrypted = xorshift64_decrypt(encrypted_payload, seed)
    end_time = time.perf_counter()
    global last_decrypt_time_ms
    last_decrypt_time_ms = (end_time - start_time) * 1000
    return decrypted

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Cops Tracker</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #0a0a0a; color: #fff; display: flex; height: 100vh; }
        .sidebar { width: 350px; background: #1a1a1a; padding: 20px; overflow-y: auto; border-right: 2px solid #333; }
        .main-content { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
        h1 { color: #4CAF50; font-size: 20px; margin-bottom: 15px; }
        .map-selector { margin: 15px 0; }
        .map-selector label { display: block; margin-bottom: 6px; color: #4CAF50; font-weight: bold; font-size: 12px; }
        .map-selector select { width: 100%; padding: 8px; background: #2a2a2a; color: #fff; border: 2px solid #4CAF50; border-radius: 5px; font-size: 13px; }
        button { width: 100%; background: #FF5722; color: white; border: none; padding: 10px; margin: 5px 0; cursor: pointer; border-radius: 5px; font-size: 13px; font-weight: bold; }
        button:hover { background: #E64A19; }
        button:disabled { background: #666; cursor: not-allowed; }
        button.reset { background: #F44336; }
        button.reset:hover { background: #D32F2F; }
        .map-wrapper { position: relative; border: 3px solid #4CAF50; border-radius: 8px; box-shadow: 0 0 20px rgba(76, 175, 80, 0.3); }
        .map-image { display: block; max-width: 90vmin; max-height: 90vmin; }
        .player-dot { 
            position: absolute; width: 16px; height: 16px;
            background: radial-gradient(circle, #ff4444 0%, #cc0000 70%, #880000 100%);
            border: 2px solid rgba(255, 255, 255, 0.9); border-radius: 50%;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 8px rgba(255, 68, 68, 0.8), 0 0 16px rgba(255, 68, 68, 0.4), inset 0 -2px 4px rgba(0, 0, 0, 0.3);
            z-index: 10;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
        }
        .player-dot::before { content: ''; position: absolute; top: 50%; left: 50%; width: 6px; height: 6px; background: rgba(255, 255, 255, 0.8); border-radius: 50%; transform: translate(-50%, -50%); }
        .player-dot::after { content: ''; position: absolute; top: -6px; left: -6px; right: -6px; bottom: -6px; border: 2px solid rgba(255, 68, 68, 0.3); border-radius: 50%; animation: radar-pulse 2s ease-out infinite; }
        @keyframes radar-pulse { 0% { transform: scale(1); opacity: 1; } 100% { transform: scale(2); opacity: 0; } }
    </style>
</head>
<body>
    <div class="sidebar">
        <h1>srkorwho</h1>
        <div class="map-selector"> <label>Select Map:</label> <select id="map-select" onchange="changeMap()"></select> </div>
        <button onclick="bruteforce()" id="bruteforce-btn">Connect</button>
        <button onclick="reset()" class="reset" id="reset-btn" disabled>Disconnect</button>
    </div>
    <div class="main-content">
        <div class="map-wrapper" id="map-wrapper">
            <img id="map-image" class="map-image" src="/static/maps/bureau.png" alt="Map">
        </div>
    </div>
    <script>
        let currentMap = null, maps = [], socket = null, playerDots = {};
        function initWebSocket() {
            socket = io();
            socket.on('connect', () => console.log('WebSocket connected'));
            socket.on('players_update', data => updatePlayersSmooth(data.players));
            socket.on('disconnect', () => console.log('WebSocket disconnected'));
        }
        function updatePlayersSmooth(players) {
            const wrapper = document.getElementById('map-wrapper');
            Object.keys(playerDots).forEach(key => {
                const playerIndex = parseInt(key);
                if (!players[playerIndex] || players[playerIndex].pixel_x === null) {
                    if (playerDots[key]) { playerDots[key].remove(); delete playerDots[key]; }
                }
            });
            if (players && players.length > 0) {
                players.forEach((player, idx) => {
                    if (player.pixel_x !== null && player.pixel_y !== null) {
                        if (!playerDots[idx]) {
                            const dot = document.createElement('div');
                            dot.className = 'player-dot';
                            dot.style.left = player.pixel_x + 'px';
                            dot.style.top = player.pixel_y + 'px';
                            wrapper.appendChild(dot);
                            playerDots[idx] = dot;
                        } else {
                            playerDots[idx].style.left = player.pixel_x + 'px';
                            playerDots[idx].style.top = player.pixel_y + 'px';
                        }
                    }
                });
            }
        }
        function loadMaps() {
            fetch('/maps').then(r => r.json()).then(data => {
                maps = data.maps; currentMap = data.current;
                const select = document.getElementById('map-select');
                select.innerHTML = '';
                maps.forEach(map => {
                    const option = document.createElement('option');
                    option.value = map.name; option.textContent = map.display_name;
                    if (map.name === currentMap.name) { option.selected = true; }
                    select.appendChild(option);
                });
                updateMapImage();
            });
        }
        function changeMap() {
            const mapName = document.getElementById('map-select').value;
            fetch('/set_map', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({map_name: mapName}) })
            .then(r => r.json()).then(data => { currentMap = data.map; updateMapImage(); });
        }
        function updateMapImage() {
            if (!currentMap) return;
            document.getElementById('map-image').src = '/static/maps/' + currentMap.image + '?v=' + Date.now();
            Object.values(playerDots).forEach(dot => dot.remove());
            playerDots = {};
        }
        function updateStatus() {
            fetch('/status').then(r => r.json()).then(data => {
                document.getElementById('reset-btn').disabled = !data.xor_key;
                if (!data.is_bruteforcing) {
                    document.getElementById('bruteforce-btn').disabled = false;
                }
            });
        }
        function bruteforce() {
            document.getElementById('bruteforce-btn').disabled = true;
            fetch('/bruteforce', {method: 'POST'}).then(r => r.json()).then(data => {
                console.log(data);
            });
        }
        function reset() {
            fetch('/reset', {method: 'POST'}).then(r => r.json()).then(data => {
                Object.values(playerDots).forEach(dot => dot.remove());
                playerDots = {};
            });
        }
        initWebSocket(); loadMaps(); setInterval(updateStatus, 500);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/maps')
def get_maps():
    return jsonify({'maps': MAPS, 'current': current_map})

@app.route('/set_map', methods=['POST'])
def set_map():
    global current_map, latest_player_positions
    data = request.json
    map_name = data.get('map_name')
    for m in MAPS:
        if m['name'] == map_name:
            current_map = m
            if latest_player_positions:
                for player in latest_player_positions:
                    pixel_x, pixel_y = convert_to_map_pixels(player['x_real'], player['z_real'], current_map)
                    player['pixel_x'] = pixel_x
                    player['pixel_y'] = pixel_y
            return jsonify({'success': True, 'map': current_map})
    return jsonify({'success': False})

@app.route('/status')
def status():
    global xor_key_global, bruteforce_progress, is_bruteforcing, latest_player_positions
    response = {
        'count': packet_counter, 'xor_key': xor_key_global,
        'is_bruteforcing': is_bruteforcing, 'progress': bruteforce_progress,
        'player_count': len(latest_player_positions), 'players': latest_player_positions
    }
    return jsonify(response)

@app.route('/bruteforce', methods=['POST'])
def bruteforce():
    print("[*] /bruteforce route called.")
    global bruteforce_thread, is_bruteforcing 
    
    if not latest_packet:
        print("[!] /bruteforce: latest_packet not found!")
        return jsonify({'success': False, 'error': 'No packet available'})
    
    if is_bruteforcing:
         print("[!] /bruteforce: Already running.")
         return jsonify({'success': False, 'error': 'Already bruteforcing'})

    bruteforce_thread = threading.Thread(target=bruteforce_with_cpp, args=(latest_packet,), daemon=True)
    bruteforce_thread.start()
    
    print("[*] /bruteforce: Bruteforce thread started.")
    return jsonify({'success': True, 'message': 'Bruteforce started'}) 

@app.route('/reset', methods=['POST'])
def reset():
    global xor_key_global, latest_player_positions, last_decrypt_time_ms
    xor_key_global = None
    latest_player_positions = []
    last_decrypt_time_ms = 0
    socketio.emit('players_update', {'count': 0, 'players': []})
    print("\n[🔄] XOR key reset!")
    return jsonify({'success': True})

def check_pattern(data_hex):
    if len(data_hex) < 12: return False
    if (data_hex[0:1] in '0123456789abcdef' and
        data_hex[1:2] == '0' and
        data_hex[2:4] == '00' and 
        data_hex[4:6] == '07' and 
        data_hex[6:8] == '00'):
        return True
    return False

def simple_packet_handler(packet):
    global packet_counter, latest_packet, xor_key_global
    
    try:
        if packet.haslayer(Raw): 
            data = bytes(packet[Raw].load)
            data_hex = data.hex()

            if len(data) >= 40:
                if check_pattern(data_hex): 
                    packet_counter += 1
                    latest_packet = data
                    
                    if xor_key_global:
                        decrypted = decrypt_incoming_packet(data)
                        if decrypted:
                            decrypted_hex = decrypted.hex()
                            player_info = parse_player_positions(decrypted_hex) 
                                
    except Exception as e:
        print(f"[!] Handler Error: {e}")
        pass

def start_sniffing(): 
    bpf_filter = "udp and src net 172.65.0.0/16" 
    print("\n" + "="*60)
    print("Starting packet capture...")
    print("="*60 + "\n")

    try:
        sniff(iface="wg0", filter=bpf_filter, prn=simple_packet_handler, store=0) 
    except Exception as e:
        print(f"[!] Sniffing Error: {e}")
        print("[!] Make sure you are running with 'sudo'!")


if __name__ == '__main__':
    os.makedirs('static/maps', exist_ok=True)

    sniffer_thread = threading.Thread(
        target=start_sniffing,
        daemon=True
    )
    sniffer_thread.start()

    print("[*] Server starting at http://0.0.0.0:5000...")
    socketio.run(app, host='0.0.0.0', port=5000)
