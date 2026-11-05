import io
import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP, DNS
from datetime import datetime

st.set_page_config(page_title="Network Packet Visualiser", page_icon="📡", layout="wide")
st.title("📡  Network Packet Visualiser")
