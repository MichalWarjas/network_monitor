# Network Traffic Dashboard

A **real-time network traffic capture and analysis** dashboard built with Streamlit, Scapy, pandas, and Plotly. Visualize live packets, protocol distribution, traffic volume, and top talkers in a web UI.

## Features

- Live packet capture on a selected network interface
- Protocol distribution pie chart
- Traffic volume bar chart by protocol
- Top source and destination IPs by packet count
- Start/stop controls and adjustable refresh interval

## Installation

1. Clone the repository:

   ```bash
   git clone <repo_url>
   cd network_graph
   ```

2. Create and activate a Python virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. (Optional) Grant raw-socket permissions to your Python interpreter to capture packets without `sudo`:

   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
   ```

## Running the App

With the virtual environment activated, you can launch the Streamlit dashboard:

```bash
streamlit run main.py
```

If you encounter permission errors or need to run with elevated privileges, use:

```bash
sudo $(which python) -m streamlit run main.py
```

## Usage

- Select a network interface in the sidebar (e.g., `eth0`, `wlan0`).
- Click **Start Capture** to begin sniffing.
- Click **Stop Capture** to end the session.
- Adjust the refresh interval as needed.

## Requirements

See `requirements.txt` for a full list of Python packages and versions.

## Notes

- Running packet capture may require root privileges or elevated capabilities.
- Not all environments (e.g., containerized or restricted hosts) support raw socket capture.
