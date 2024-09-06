
# Intrusion Detection Tool for Your PC (Written in Python)


import os
import time
import socket
import psutil
from datetime import datetime
import logging

# Setup logging to record suspicious activity
LOG_FILE = 'intrusion_log.txt'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Function to detect new processes
def detect_new_processes(last_processes):
    current_processes = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'username', 'create_time'])}
    new_processes = {}
    for pid, info in current_processes.items():
        if pid not in last_processes:
            new_processes[pid] = info
    return new_processes, current_processes

# Function to detect suspicious ports (commonly used by hackers)
def detect_suspicious_ports():
    suspicious_ports = [21, 22, 23, 80, 135, 443, 445, 3389]  # Common hacking ports
    suspicious_connections = []
    for conn in psutil.net_connections():
        if conn.laddr.port in suspicious_ports:
            suspicious_connections.append(conn)
    return suspicious_connections

# Function to detect high CPU or RAM usage (could be signs of malware)
def detect_high_usage(threshold=80):
    cpu_usage = psutil.cpu_percent(interval=1)
    ram_usage = psutil.virtual_memory().percent
    return cpu_usage > threshold or ram_usage > threshold, cpu_usage, ram_usage

# Function to detect active network connections and unusual IP addresses
def detect_unusual_ips(trusted_ips):
    suspicious_ips = []
    for conn in psutil.net_connections():
        if conn.status == psutil.CONN_ESTABLISHED:
            remote_ip = conn.raddr.ip if conn.raddr else None
            if remote_ip and remote_ip not in trusted_ips:
                suspicious_ips.append(remote_ip)
    return suspicious_ips

# Function to monitor the system
def monitor_system():
    trusted_ips = ['127.0.0.1']  # Add trusted IPs here
    last_processes = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'username', 'create_time'])}

    while True:
        # 1. Detect new processes
        new_processes, last_processes = detect_new_processes(last_processes)
        if new_processes:
            logging.info(f'New processes detected: {new_processes}')
            print(f'[ALERT] New processes detected: {new_processes}')

        # 2. Detect suspicious ports
        suspicious_ports = detect_suspicious_ports()
        if suspicious_ports:
            logging.info(f'Suspicious ports detected: {suspicious_ports}')
            print(f'[ALERT] Suspicious ports detected: {suspicious_ports}')

        # 3. Detect high CPU or RAM usage
        is_high_usage, cpu_usage, ram_usage = detect_high_usage()
        if is_high_usage:
            logging.info(f'High resource usage detected - CPU: {cpu_usage}%, RAM: {ram_usage}%')
            print(f'[ALERT] High resource usage detected - CPU: {cpu_usage}%, RAM: {ram_usage}%')

        # 4. Detect unusual IP addresses
        suspicious_ips = detect_unusual_ips(trusted_ips)
        if suspicious_ips:
            logging.info(f'Suspicious IPs detected: {suspicious_ips}')
            print(f'[ALERT] Suspicious IPs detected: {suspicious_ips}')

        # Sleep for a while before checking again
        time.sleep(10)

if __name__ == '__main__':
    print('Intrusion Detection System is now running...')
    logging.info('Intrusion Detection System started')
    monitor_system()
