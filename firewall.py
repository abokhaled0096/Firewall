import tkinter as tk  # GUI library for building the interface
from tkinter import ttk, messagebox  # ttk for advanced widgets, messagebox for alerts
import threading  # To run background tasks (e.g., packet sniffing)
import scapy.all as scapy  # For network packet sniffing and analysis
import socket  # For IP address validation
import time  # For delays in simulations
import logging  # For logging actions to a file
from collections import Counter  # To count and analyze traffic patterns

# Global variables
firewall_rules = []  # List to store user-defined firewall rules
blocked_ips = set()  # Set to store manually/automatically blocked IPs
traffic_logs = []  # List to store logs of network traffic
stop_sniffing = False  # Flag to control packet sniffing process
traffic_analysis_data = Counter()  # Dictionary-like object to count packets per IP
ddos_detection_enabled = False  # Boolean to toggle DDoS detection

#save logs in 'firewall_logs.txt'
logging.basicConfig(
    filename='firewall_logs.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Function to match a packet against firewall rules
def match_packet_with_rules(packet):
    # Only process packets with an IP layer
    if not packet.haslayer(scapy.IP):
        return True

    # packet details
    src_ip = packet[scapy.IP].src  # Source IP address
    dst_ip = packet[scapy.IP].dst  # Destination IP address
    protocol = packet[scapy.IP].proto  # Protocol number (e.g., TCP, UDP)
    src_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else None  # Source port (TCP only)
    dst_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else None  # Destination port (TCP only)

    # Check the packet rule
    for rule in firewall_rules:
        rule_type, rule_value = rule.split(":")  # Split rule into type and value
        if rule_type == "src_ip" and src_ip == rule_value:
            return False  # Block packet if source IP matches rule
        elif rule_type == "dst_ip" and dst_ip == rule_value:
            return False  # Block packet if destination IP matches rule
        elif rule_type == "src_port" and src_port == int(rule_value):
            return False  # Block packet if source port matches rule
        elif rule_type == "dst_port" and dst_port == int(rule_value):
            return False  # Block packet if destination port matches rule
        elif rule_type == "protocol" and protocol == int(rule_value):
            return False  # Block packet if protocol matches rule

    # Allow packet if no rules matched
    return True

# Function to handle incoming packets
def packet_handler(packet):
    global traffic_logs, traffic_analysis_data  # Use global logs and traffic data

    # Default action is to allow the packet
    action = "Allowed"
    block_reason = ""

    # Check if packet matches any blocking rules
    if not match_packet_with_rules(packet):
        action = "Blocked"
        block_reason = "Matched Firewall Rule"

    # Extract IP addresses
    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
    dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"

    # Block packet if the source or destination IP is in the blocked list
    if src_ip in blocked_ips or dst_ip in blocked_ips:
        action = "Blocked"
        block_reason = "IP Manually Blocked"

    # Log the action (blocked or allowed) with packet details
    protocol = packet[scapy.IP].proto if packet.haslayer(scapy.IP) else "Unknown"
    if action == "Blocked":
        logging.info(f"Packet Blocked - Src IP: {src_ip}, Dst IP: {dst_ip}, Protocol: {protocol}, Reason: {block_reason}")
    else:
        logging.info(f"Packet Allowed - Src IP: {src_ip}, Dst IP: {dst_ip}, Protocol: {protocol}")

    # Save the action to traffic logs
    traffic_logs.append((action, src_ip, dst_ip, protocol, block_reason))

    # Update the traffic count for the source IP
    traffic_analysis_data[src_ip] += 1

    # Write logs to a file for persistence
    with open("logs.txt", "a") as log_file:
        log_file.write(f"{action}\t{src_ip}\t{dst_ip}\t{protocol}\t{block_reason}\n")

    # Block packet by returning False
    if action == "Blocked":
        return False
    return True

# Function to analyze traffic patterns for DDoS detection
def analyze_traffic():
    global traffic_analysis_data

    if not ddos_detection_enabled:
        return  # Exit if DDoS detection is disabled

    malicious_ips = []  # List of IPs to block
    threshold = 10  # Packets per IP threshold for DDoS detection

    # Identify IPs with packet counts exceeding the threshold
    for ip, count in traffic_analysis_data.items():
        if count > threshold:
            malicious_ips.append(ip)

    # Block identified IPs and update the blocked list
    for ip in malicious_ips:
        if ip not in blocked_ips:
            blocked_ips.add(ip)
            blocked_ips_listbox.insert(tk.END, ip)  # Update the GUI
            logging.warning(f"IP {ip} automatically blocked due to DDoS detection.")
            messagebox.showinfo("DDoS Detected", f"IP {ip} has been blocked due to suspicious activity.")

    # Reset traffic data for the next analysis cycle
    traffic_analysis_data.clear()

# Function to toggle DDoS detection on or off
def toggle_ddos_detection():
    global ddos_detection_enabled
    ddos_detection_enabled = not ddos_detection_enabled
    status = "enabled" if ddos_detection_enabled else "disabled"
    messagebox.showinfo("DDoS Detection", f"DDoS detection is now {status}.")
# Function to start sniffing packets
def start_sniffing():
    global stop_sniffing
    stop_sniffing = False  # Reset the stop flag
    sniff_button.config(state=tk.DISABLED)  # Disable the sniffing button while sniffing is active

    # Threaded function to sniff packets in the background
    def sniff_packets():
        scapy.sniff(
            prn=packet_handler,  # Process each packet with the packet handler
            store=False,  # Do not store packets in memory
            stop_filter=lambda _: stop_sniffing,  # Stop sniffing if the stop flag is set
            filter="ip"  # Filter to capture only IP packets
        )

    # Start sniffing in a separate thread to avoid freezing the GUI
    threading.Thread(target=sniff_packets, daemon=True).start()

# Function to stop sniffing packets
def stop_sniffing_action():
    global stop_sniffing
    stop_sniffing = True  # Set the stop flag
    sniff_button.config(state=tk.NORMAL)  # Re-enable the sniffing button

# Function to add a firewall rule
def add_rule():
    rule = rule_entry.get()  # Get the rule from the input field
    if rule:
        firewall_rules.append(rule)  # Add the rule to the firewall rules list
        rules_listbox.insert(tk.END, rule)  # Update the GUI listbox
        rule_entry.delete(0, tk.END)  # Clear the input field
        messagebox.showinfo("Rule Added", f"Rule '{rule}' has been added successfully.")  # Notify the user

# Function to block an IP address
def block_ip():
    ip = block_ip_entry.get()  # Get the IP address from the input field
    if ip:
        try:
            socket.inet_aton(ip)  # Validate the IP address format
            blocked_ips.add(ip)  # Add the IP to the blocked IPs set
            blocked_ips_listbox.insert(tk.END, ip)  # Update the GUI listbox
            block_ip_entry.delete(0, tk.END)  # Clear the input field
            logging.info(f"IP {ip} manually blocked.")  # Log the action
            messagebox.showinfo("IP Blocked", f"IP address '{ip}' has been blocked successfully.")  # Notify the user
        except socket.error:
            messagebox.showerror("Invalid IP", "The IP address format is invalid.")  # Show error for invalid IP format

# Function to view logs in a separate window
def view_logs():
    logs_window = tk.Toplevel(root)  # Create a new top-level window
    logs_window.title("Traffic Logs")  # Set the window title
    logs_window.geometry("900x600")  # Set the window size

    # Create a table to display logs
    log_table = ttk.Treeview(
        logs_window,
        columns=("Action", "Source IP", "Destination IP", "Protocol", "Reason"),
        show="headings"
    )
    # Set up table heads
    log_table.heading("Action", text="Action")
    log_table.heading("Source IP", text="Source IP")
    log_table.heading("Destination IP", text="Destination IP")
    log_table.heading("Protocol", text="Protocol")
    log_table.heading("Reason", text="Reason")

    log_table.pack(fill=tk.BOTH, expand=True)  # Allow the table to resize with the window

    # Populate the table with traffic logs
    for log in traffic_logs:
        log_table.insert("", tk.END, values=log)

# Function to clear all logs
def clear_logs():
    traffic_logs.clear()  # Clear the traffic logs list
    # Overwrite the log file with the header
    with open("logs.txt", "w") as log_file:
        log_file.write("Action\tSource IP\tDestination IP\tProtocol\tReason\n")
    messagebox.showinfo("Logs Cleared", "All traffic logs have been cleared.")  # Notify the user

# Function to delete a selected firewall rule
def delete_rule():
    selected_rule = rules_listbox.curselection()  # Get the selected rule from the GUI listbox
    if selected_rule:
        rule = rules_listbox.get(selected_rule)  # Retrieve the rule text
        rules_listbox.delete(selected_rule)  # Remove the rule from the GUI listbox
        firewall_rules.remove(rule)  # Remove the rule from the global rules list
        messagebox.showinfo("Rule Deleted", f"Rule '{rule}' has been deleted successfully.")  # Notify the user

# Function to delete a selected blocked IP
def delete_blocked_ip():
    selected_ip = blocked_ips_listbox.curselection()  # Get the selected IP from the GUI listbox
    if selected_ip:
        ip = blocked_ips_listbox.get(selected_ip)  # Retrieve the IP text
        blocked_ips_listbox.delete(selected_ip)  # Remove the IP from the GUI listbox
        blocked_ips.remove(ip)  # Remove the IP from the global blocked IPs set
        messagebox.showinfo("IP Unblocked", f"IP address '{ip}' has been unblocked successfully.")  # Notify the user

# Function to simulate network traffic for testing
def simulate_traffic():
    demo_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]  # Sample IPs to simulate traffic
    for _ in range(200):  # Simulate 200 packets
        if ddos_detection_enabled:  # If DDoS detection is enabled
            for ip in demo_ips:  # Increment traffic count for each demo IP
                traffic_analysis_data[ip] += 1
        time.sleep(0.05)  # Small delay to mimic real traffic

# Function to analyze traffic periodically in a background thread
def run_traffic_analysis():
    while True:  # Infinite loop for continuous monitoring
        if not stop_sniffing:  # If sniffing is active
            analyze_traffic()  # Analyze the traffic patterns
        time.sleep(10)  # Wait 10 seconds before the next analysis

# Start a thread to analyze traffic patterns continuously
threading.Thread(target=run_traffic_analysis, daemon=True).start()

# --- GUI Setup ---
root = tk.Tk()  # Initialize the main application window
root.title("Personal Firewall")  # Set the title of the window
root.geometry("600x900")  # Set the window size

# Add labels, input fields, buttons, and listboxes for various functionalities
rules_label = tk.Label(root, text="Firewall Rules (e.g., src_ip:<IP>, dst_ip:<IP>, protocol:<protocol>)", font=("Arial", 12))
rules_label.pack(pady=10)

rule_frame = tk.Frame(root)
rule_frame.pack()

rule_entry = tk.Entry(rule_frame, width=30)
rule_entry.pack(side=tk.LEFT, padx=5)

add_rule_button = tk.Button(rule_frame, text="Add Rule", command=add_rule, bg="green", fg="white")
add_rule_button.pack(side=tk.LEFT, padx=5)

delete_rule_button = tk.Button(rule_frame, text="Delete Rule", command=delete_rule, bg="red", fg="white")
delete_rule_button.pack(side=tk.LEFT, padx=5)

rules_listbox = tk.Listbox(root, width=50, height=10)
rules_listbox.pack(pady=10)

block_ip_label = tk.Label(root, text="Block IP Address", font=("Arial", 14))
block_ip_label.pack(pady=10)

block_ip_frame = tk.Frame(root)
block_ip_frame.pack()

block_ip_entry = tk.Entry(block_ip_frame, width=30)
block_ip_entry.pack(side=tk.LEFT, padx=5)

block_ip_button = tk.Button(block_ip_frame, text="Block IP", command=block_ip, bg="red", fg="white")
block_ip_button.pack(side=tk.LEFT, padx=5)

delete_blocked_ip_button = tk.Button(block_ip_frame, text="Delete IP", command=delete_blocked_ip, bg="orange", fg="white")
delete_blocked_ip_button.pack(side=tk.LEFT, padx=5)

blocked_ips_listbox = tk.Listbox(root, width=50, height=8)
blocked_ips_listbox.pack(pady=10)

logs_button = tk.Button(root, text="View Logs", command=view_logs, bg="blue", fg="white")
logs_button.pack(pady=5)

clear_logs_button = tk.Button(root, text="Clear Logs", command=clear_logs, bg="orange", fg="white")
clear_logs_button.pack(pady=5)

sniff_button = tk.Button(root, text="Start Sniffing", command=start_sniffing, bg="green", fg="white")
sniff_button.pack(pady=10)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing_action, bg="red", fg="white")
stop_button.pack(pady=10)

simulate_button = tk.Button(root, text="Simulate Traffic", command=simulate_traffic, bg="purple", fg="white")
simulate_button.pack(pady=10)

ddos_button = tk.Button(root, text="Toggle DDoS Detection", command=toggle_ddos_detection, bg="purple", fg="white")
ddos_button.pack(pady=10)

root.mainloop()  # Start the main event loop for the GUI
