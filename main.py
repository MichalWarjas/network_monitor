# main.py
import streamlit as st
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP
import threading
import time
from collections import Counter
import socket
import plotly.express as px
from datetime import datetime
import logging  # Added for debugging

# Configure logging for debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Global Variables ---
# Use a thread-safe container for packets
class PacketStore:
    def __init__(self):
        self.packets = []
        self.lock = threading.Lock()
    
    def add_packet(self, packet_info):
        with self.lock:
            self.packets.append(packet_info)
            logger.debug(f"Added packet: {packet_info['Source IP']} → {packet_info['Destination IP']} ({packet_info['Protocol Name']})")
    
    def get_packets(self):
        with self.lock:
            packets = self.packets.copy()
            logger.debug(f"Retrieved {len(packets)} packets from store")
            return packets
    
    def clear(self):
        with self.lock:
            count = len(self.packets)
            self.packets = []
            logger.debug(f"Cleared {count} packets from store")

# Create or retrieve persistent packet store across reruns
if 'packet_store' not in st.session_state:
    st.session_state.packet_store = PacketStore()
packet_store = st.session_state.packet_store
stop_sniffing_event = threading.Event()
capture_thread = None
protocol_names = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
logger.debug(f"Initialized protocol names: {protocol_names}")

# --- Packet Sniffing Logic ---
def get_protocol_name(protocol_number):
    """Gets the human-readable name for a protocol number."""
    return protocol_names.get(protocol_number, str(protocol_number))

def packet_callback(packet):
    """Callback function processed for each captured packet."""
    global packet_store
    
    # Store in thread-safe container instead of directly in session state
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = get_protocol_name(proto_num)
        length = len(packet)
        timestamp = packet.time

        packet_info = {
            "Timestamp": timestamp,  # Store as raw timestamp
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol Number": proto_num,
            "Protocol Name": proto_name,
            "Length": length
        }
        
        # Store in thread-safe container
        packet_store.add_packet(packet_info)
        # For debugging only
        logger.debug(f"Packet captured: {src_ip} -> {dst_ip} ({proto_name})")

def start_sniffing(interface=None):
    """Starts packet sniffing in a separate thread."""
    global stop_sniffing_event
    stop_sniffing_event.clear()
    logger.debug(f"Starting sniffing on interface: {interface if interface else 'default'}")
    try:
        sniff(prn=packet_callback, store=0, stop_filter=lambda p: stop_sniffing_event.is_set(), iface=interface)
        logger.debug("Sniffing stopped.")
    except OSError as e:
        st.error(f"Error starting capture: {e}. Try running with sudo or check interface name.")
        logger.error(f"Error starting capture: {e}")
    except Exception as e:
        st.error(f"An unexpected error occurred during sniffing: {e}")
        logger.error(f"Unexpected error during sniffing: {e}")

def stop_sniffing():
    """Signals the sniffing thread to stop."""
    global stop_sniffing_event, capture_thread
    if capture_thread and capture_thread.is_alive():
        logger.debug("Stopping sniffing...")
        stop_sniffing_event.set()
        capture_thread.join(timeout=2)
        if capture_thread.is_alive():
            logger.warning("Sniffing thread did not stop gracefully.")
        capture_thread = None
        logger.debug("Capture thread joined.")
    else:
        logger.debug("Sniffing not running or thread already stopped.")

# --- Streamlit UI ---
st.set_page_config(layout="wide", page_title="Network Traffic Dashboard")

# Initialize session state variables
if 'capture_running' not in st.session_state:
    st.session_state.capture_running = False
if 'captured_packets' not in st.session_state:
    st.session_state.captured_packets = []

# This function will be called to update the captured packets in the session state
def update_packet_data():
    new_packets = packet_store.get_packets()
    if new_packets:
        # Add new packets to session state
        st.session_state.captured_packets.extend(new_packets)
        # Clear the global container to avoid duplicates
        packet_store.clear()
        logger.debug(f"Updated session state with {len(new_packets)} new packets. Total: {len(st.session_state.captured_packets)}")
    return len(new_packets) > 0

# Call update function at the start of each rerun
packets_updated = update_packet_data()

st.title("📊 Real-Time Network Traffic Dashboard")
st.markdown("""
This dashboard captures and analyzes network traffic in real-time (or near real-time).
**Note:** Packet capture requires appropriate permissions (e.g., running as root/administrator)
and might not work in all environments (like web-based platforms).
""")

# --- Sidebar for Controls ---
st.sidebar.header("Capture Controls")
try:
    import psutil
    interfaces = list(psutil.net_if_addrs().keys())
    selected_interface = st.sidebar.selectbox("Select Network Interface", interfaces, index=0)
except ImportError:
    st.sidebar.warning("`psutil` not installed. Cannot list interfaces. Please enter manually.")
    selected_interface = st.sidebar.text_input("Enter Network Interface Name (e.g., eth0, en0, Wi-Fi)", "")
except Exception as e:
    st.sidebar.error(f"Could not get interfaces: {e}")
    selected_interface = st.sidebar.text_input("Enter Network Interface Name (e.g., eth0, en0, Wi-Fi)", "")

col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("Start Capture", key="start"):
        if capture_thread is None or not capture_thread.is_alive():
            st.session_state.capture_running = True
            capture_thread = threading.Thread(target=start_sniffing, args=(selected_interface,), daemon=True)
            capture_thread.start()
            st.sidebar.success(f"Capture started on {selected_interface or 'default'}...")
        else:
            st.sidebar.warning("Capture is already running.")

with col2:
    if st.button("Stop Capture", key="stop"):
        if capture_thread and capture_thread.is_alive():
            stop_sniffing()
            st.session_state.capture_running = False
            st.sidebar.success("Capture stopped.")
        else:
            st.sidebar.warning("Capture is not running.")

# Auto-refresh interval
refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 1, 10, 5)

# Auto-refresh mechanism
st.sidebar.text(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

# --- Main Dashboard Area ---
placeholder = st.empty()

with placeholder.container():
    if not st.session_state.captured_packets:
        st.info("No packets captured yet. Start the capture or wait for packets.")
        if st.session_state.capture_running:
             st.warning("Capture is running, but no IP packets detected yet.")
    else:
        # Create DataFrame from captured packets
        df = pd.DataFrame(st.session_state.captured_packets)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')  # Convert to datetime
        df = df.sort_values(by="Timestamp", ascending=False) # Sort by most recent

        st.subheader(f"Live Packet Feed ({len(df)} packets captured)")
        st.dataframe(df.head(20), use_container_width=True) # Display recent packets

        st.subheader("Traffic Analysis")
        col_a, col_b = st.columns(2)

        with col_a:
            # Protocol Distribution Pie Chart
            st.markdown("##### Protocol Distribution")
            protocol_counts = df['Protocol Name'].value_counts()
            if not protocol_counts.empty:
                fig_proto = px.pie(protocol_counts, values=protocol_counts.values, names=protocol_counts.index,
                                   title="Packet Count by Protocol")
                fig_proto.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig_proto, use_container_width=True)
            else:
                st.info("No protocol data to display.")

        with col_b:
             # Traffic Volume by Protocol Bar Chart
            st.markdown("##### Traffic Volume (Bytes) by Protocol")
            volume_by_proto = df.groupby('Protocol Name')['Length'].sum().sort_values(ascending=False)
            if not volume_by_proto.empty:
                fig_volume = px.bar(volume_by_proto, x=volume_by_proto.index, y=volume_by_proto.values,
                                    title="Total Data Volume by Protocol", labels={'y': 'Total Bytes', 'x': 'Protocol'})
                st.plotly_chart(fig_volume, use_container_width=True)
            else:
                st.info("No volume data to display.")

        # Top Talkers (Source IPs)
        st.markdown("##### Top Source IPs (by Packet Count)")
        top_sources = df['Source IP'].value_counts().head(10)
        if not top_sources.empty:
            fig_sources = px.bar(top_sources, x=top_sources.index, y=top_sources.values,
                                 title="Top 10 Source IPs by Packet Count", labels={'y': 'Packet Count', 'x': 'Source IP'})
            st.plotly_chart(fig_sources, use_container_width=True)
        else:
            st.info("No source IP data to display.")

        # Top Destinations (Destination IPs)
        st.markdown("##### Top Destination IPs (by Packet Count)")
        top_destinations = df['Destination IP'].value_counts().head(10)
        if not top_destinations.empty:
            fig_dest = px.bar(top_destinations, x=top_destinations.index, y=top_destinations.values,
                              title="Top 10 Destination IPs by Packet Count", labels={'y': 'Packet Count', 'x': 'Destination IP'})
            st.plotly_chart(fig_dest, use_container_width=True)
        else:
            st.info("No destination IP data to display.")

# Setup auto-refresh using Streamlit's own rerun mechanism
time.sleep(refresh_interval)
st.rerun()

