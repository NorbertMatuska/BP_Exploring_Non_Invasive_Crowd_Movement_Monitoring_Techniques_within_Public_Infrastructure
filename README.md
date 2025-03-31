# Wi-Fi Crowd Monitoring & Frame Analysis

This repository contains Python code and helper scripts to:
1. **Parse** raw 802.11 frames 
2. **Analyze** their metadata  
3. **Insert** structured records into ClickHouse for downstream crowd-movement analytics  
4. **Perform** higher-level analysis such as static device detection, vendor counting, and crowd estimation

It is designed as part of a Bachelor's Thesis on non-invasive Wi-Fi crowd monitoring in public infrastructure.

---

## Overview

This project demonstrates a pipeline for **passive crowd monitoring** by capturing raw IEEE 802.11 frames from Wi-Fi devices. After extracting key frame fields (type, subtype, source/destination MAC, RSSI, etc.), the code stores these records in a ClickHouse database for further data mining. From there, we explore:

- **Heatmap generation**: Visualizing data presence over time (per-minute aggregates).  
- **Vendor analysis**: Mapping OUIs (first three bytes of MAC addresses) to hardware vendors.  
- **Static device detection**: Identifying likely fixed devices by analyzing RSSI variance.  
- **Crowd counting**: Estimating the number of unique devices over time, optionally filtering out “static” or “always present” signals.  
- **Cluster-based methods**: Using DBSCAN to detect outliers or static devices by presence ratio, RSSI means, and other aggregated features.  

---

## Features

1. **802.11 Frame Decoding**  
   - Converts base64-encoded headers into structured data (protocol version, addresses, QoS flags, etc.).
   - Supports probe request parsing to retrieve SSIDs, supported rates, and vendor elements.

2. **ClickHouse Integration**  
   - Code for chunked insertion from a raw table into a structured parsed table.
   - Automatic creation of schema (if needed).

3. **Data Aggregation & Analysis**  
   - Minute-level heatmap for each device (visual overview of data presence).
   - Vendor distribution counts (bar chart with log scale).
   - Automatic grouping by MAC addresses and sniffer location (device).
   - Simple static-device detection function (based on RSSI variance).

4. **Crowd Counting Approaches**
   - Currently work in progress
