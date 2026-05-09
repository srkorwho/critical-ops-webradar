#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

using namespace std;

atomic<bool> found_flag(false);
atomic<uint64_t> total_checked(0);
mutex result_mutex;
uint32_t found_xor_key = 0;
uint32_t found_seed = 0;

inline vector<uint8_t> xorshift64_decrypt(const vector<uint8_t>& data, uint64_t seed) {
    vector<uint8_t> decrypted_payload = data;
    uint32_t length = data.size();
    uint64_t state = seed;
    
    uint32_t i = 0;
    while (i < length) {
        uint64_t original_state = state;
        uint64_t state_shifted_13 = (state << 13);
        uint64_t temp_xor_1 = state ^ state_shifted_13;
        uint64_t temp_v10 = temp_xor_1 ^ (temp_xor_1 >> 7);
        
        decrypted_payload[i] ^= (uint8_t)((original_state & 0xFF) ^ ((temp_xor_1 >> 7) & 0xFF));
        
        if (i + 1 < length) {
            decrypted_payload[i + 1] ^= (uint8_t)((temp_v10 >> 8) & 0xFF);
        }
        
        uint64_t state_shifted_17 = (temp_v10 << 17);
        state = temp_v10 ^ state_shifted_17;
        
        for (int j = 2; j < 8 && i + j < length; j++) {
            decrypted_payload[i + j] ^= (uint8_t)((state >> (j * 8)) & 0xFF);
        }
        
        i += 8;
    }
    
    return decrypted_payload;
}

inline bool matches_pattern(const vector<uint8_t>& data) {
    if (data.size() < 6) return false;
    if (data[0] != 0x5D) return false;
    if (data[3] != 0x00 || data[4] != 0x00) return false;
    if ((data[5] & 0xF0) != 0x80) return false;
    if (data[data.size() - 1] != 0x00) return false;
    return true;
}

void bruteforce_range(uint64_t start, uint64_t end, const vector<uint8_t>& encrypted, uint32_t mystery_int) {
    uint64_t local_checked = 0;
    
    for (uint64_t seed = start; seed < end && !found_flag; seed++) {
        vector<uint8_t> decrypted = xorshift64_decrypt(encrypted, seed);
        
        if (matches_pattern(decrypted)) {
            lock_guard<mutex> lock(result_mutex);
            if (!found_flag) {
                found_flag = true;
                found_seed = (uint32_t)seed;
                found_xor_key = mystery_int ^ seed;
            }
            return;
        }
        
        local_checked++;
        if (local_checked % 0x1000000 == 0) {
            total_checked += 0x1000000;
        }
    }
    
    total_checked += (local_checked % 0x1000000);
}

vector<uint8_t> hex_to_bytes(const string& hex_str) {
    vector<uint8_t> result;
    string clean = hex_str;
    clean.erase(remove(clean.begin(), clean.end(), ' '), clean.end());
    clean.erase(remove(clean.begin(), clean.end(), '\n'), clean.end());
    
    for (size_t i = 0; i < clean.length(); i += 2) {
        string byte_str = clean.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byte_str.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "ERROR: No packet hex provided" << endl;
        return 1;
    }
    
    string packet_hex = argv[1];
    vector<uint8_t> packet = hex_to_bytes(packet_hex);
    
    if (packet.size() < 14) {
        cerr << "ERROR: Packet too short" << endl;
        return 1;
    }
    
    vector<uint8_t> mystery(packet.begin() + 10, packet.begin() + 14);
    vector<uint8_t> encrypted(packet.begin() + 14, packet.end());
    
    uint32_t mystery_int = (mystery[0] | (mystery[1] << 8) | (mystery[2] << 16) | (mystery[3] << 24));
    
    cerr << "[*] Mystery: 0x" << hex << setfill('0') << setw(8) << mystery_int << dec << endl;
    
    unsigned int num_threads = thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 8;
    
    cerr << "[*] Using " << num_threads << " threads" << endl;
    cerr << "[*] Bruteforcing..." << endl;
    
    found_flag = false;
    total_checked = 0;
    
    auto start_time = chrono::high_resolution_clock::now();
    
    vector<thread> threads;
    uint64_t range = 0x100000000ULL / num_threads;
    
    for (unsigned int i = 0; i < num_threads; i++) {
        uint64_t start = i * range;
        uint64_t end = (i == num_threads - 1) ? 0x100000000ULL : (i + 1) * range;
        threads.emplace_back(bruteforce_range, start, end, encrypted, mystery_int);
    }
    
    thread progress_thread([&]() {
        while (!found_flag) {
            this_thread::sleep_for(chrono::seconds(1));
            uint64_t checked = total_checked.load();
            double percent = (checked / (double)0x100000000ULL) * 100.0;
            
            auto current_time = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(current_time - start_time).count();
            
            if (elapsed > 0) {
                uint64_t speed = checked / elapsed;
                uint64_t remaining = 0x100000000ULL - checked;
                uint64_t eta_seconds = remaining / (speed + 1);
                
                cerr << "\rProgress: " << fixed << setprecision(2) << percent 
                     << "% | Speed: " << (speed / 1000000) << "M/s | ETA: " 
                     << (eta_seconds / 60) << "m" << flush;
            } else {
                cerr << "\rProgress: " << fixed << setprecision(2) << percent << "%" << flush;
            }
        }
    });
    
    for (auto& t : threads) {
        t.join();
    }
    
    found_flag = true;
    progress_thread.join();
    
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::seconds>(end_time - start_time).count();
    
    if (found_xor_key != 0) {
        cout << hex << setfill('0') << setw(8) << found_xor_key << endl;
        cerr << "\n[+] FOUND! Seed: 0x" << setw(8) << found_seed 
             << ", XOR Key: 0x" << setw(8) << found_xor_key 
             << " (took " << dec << duration << "s)" << endl;
        return 0;
    }
    
    cerr << "\n[!] No match found (searched for " << duration << "s)" << endl;
    return 1;
}
