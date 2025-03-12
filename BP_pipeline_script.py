import pandas as pd
import numpy as np
import base64
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import clickhouse_connect
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

management_subtypes = {
    0:  "Association Request",
    1:  "Association Response",
    2:  "Reassociation Request",
    3:  "Reassociation Response",
    4:  "Probe Request",
    5:  "Probe Response",
    6:  "Timing Advertisement (11v)",
    7:  "Reserved",
    8:  "Beacon",
    9:  "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
    14: "Action No Ack (11e)",
    15: "Reserved"
}

control_subtypes = {
    0:   "Reserved",
    1:   "Reserved",
    2:   "Trigger",
    3:   "TACK",
    4:   "Beamforming Report Poll",
    5:   "VHT/HE NDP Announcement",
    6:   "Reserved",
    7:   "Control Wrapper",
    8:   "Block Ack Request",
    9:   "Block Ack",
    10:  "PS-Poll",
    11:  "RTS",
    12:  "CTS",
    13:  "ACK",
    14:  "CF-End",
    15:  "CF-End + CF-Ack"
}

data_subtypes = {
    0:   "Data",
    1:   "Data + CF-Ack",
    2:   "Data + CF-Poll",
    3:   "Data + CF-Ack + CF-Poll",
    4:   "Null Function (No Data)",
    5:   "CF-Ack (No Data)",
    6:   "CF-Poll (No Data)",
    7:   "CF-Ack + CF-Poll (No Data)",
    8:   "QoS Data",
    9:   "QoS Data + CF-Ack",
    10:  "QoS Data + CF-Poll",
    11:  "QoS Data + CF-Ack + CF-Poll",
    12:  "QoS Null",
    13:  "Reserved",
    14:  "Reserved",
    15:  "Reserved"
}

frame_type_map = {
    0: "Management",
    1: "Control",
    2: "Data",
    3: "Extension"
}

TRANSLATED_HEADER_COLUMNS = [
    "frame_control_raw",
    "protocol_version",
    "frame_type",
    "subtype",

    "to_ds",
    "from_ds",
    "more_frag",
    "retry",
    "power_mgmt",
    "more_data",
    "protected_frame",
    "order_flag",

    "duration_id",

    "destination_mac",
    "source_mac",
    "bssid_mac",
    "address4_mac",

    "sequence_control_raw",
    "fragment_number",
    "sequence_number",

    "qos_control_raw",
    "ht_control_raw",

    "frame_body"
]


def decode_header(header_b64):
    try:
        return base64.b64decode(header_b64)
    except Exception as e:
        print(f"Error decoding header: {e}")
        return None

def parse_probe_request(frame_body):

    pos = 0
    ies = {
        "ssid": None,
        "supported_rates": [],
        "extended_rates": [],
        "vendor_specific": []
    }

    while pos < len(frame_body):
        if pos + 1 >= len(frame_body):
            break

        element_id = frame_body[pos]
        element_len = frame_body[pos + 1]
        pos += 2

        if pos + element_len > len(frame_body):
            break

        element_data = frame_body[pos : pos + element_len]
        pos += element_len

        if element_id == 0:
            ies["ssid"] = element_data.decode("ascii", errors="ignore")
        elif element_id == 1:
            ies["supported_rates"] = _decode_supported_rates(element_data)
        elif element_id == 50:
            ies["extended_rates"] = _decode_supported_rates(element_data)
        elif element_id == 221:
            ies["vendor_specific"].append(element_data)
        else:
            pass

    return ies

def _decode_supported_rates(rate_bytes):

    rates = []
    for r in rate_bytes:
        rate_val = r & 0x7F  # strip off the 'basic rate' bit
        # each unit = 500 kbps => multiply by 0.5 to get Mbps
        rates.append(rate_val * 0.5)
    return rates

def translate_header(header_bytes):
    if not header_bytes or len(header_bytes) < 24:
        return [None] * len(TRANSLATED_HEADER_COLUMNS)

    try:
        # -----------------------------
        # Frame Control
        # -----------------------------
        frame_control_raw = int.from_bytes(header_bytes[0:2], byteorder="little")

        protocol_version =  frame_control_raw & 0b11                # bits 0-1
        frame_type       = (frame_control_raw >> 2) & 0b11          # bits 2-3
        subtype          = (frame_control_raw >> 4) & 0b1111        # bits 4-7

        # Flags
        flags = (frame_control_raw >> 8) & 0xFF

        to_ds           = bool(flags & 0b00000001)  # bit 8
        from_ds         = bool(flags & 0b00000010)  # bit 9
        more_frag       = bool(flags & 0b00000100)  # bit 10
        retry           = bool(flags & 0b00001000)  # bit 11
        power_mgmt      = bool(flags & 0b00010000)  # bit 12
        more_data       = bool(flags & 0b00100000)  # bit 13
        protected_frame = bool(flags & 0b01000000)  # bit 14
        order_flag      = bool(flags & 0b10000000)  # bit 15

        # -----------------------------
        # Type/Subtype Description
        # -----------------------------
        type_description = frame_type_map.get(frame_type, "Reserved")

        if frame_type == 0:
            subtype_description = management_subtypes.get(subtype, "Unknown")
        elif frame_type == 1:
            subtype_description = control_subtypes.get(subtype, "Unknown")
        elif frame_type == 2:
            subtype_description = data_subtypes.get(subtype, "Unknown")
        else:
            # subtype mapping for 802.11n+ is more specialized
            subtype_description = "Extension/Reserved"

        # -----------------------------
        # Duration/ID
        # -----------------------------
        duration_id = int.from_bytes(header_bytes[2:4], byteorder="little")

        # -----------------------------
        # Addresses
        # -----------------------------
        address1 = _format_mac(header_bytes[4:10])
        address2 = _format_mac(header_bytes[10:16])
        address3 = _format_mac(header_bytes[16:22])

        # Sequence Control
        sequence_control_raw = int.from_bytes(header_bytes[22:24], byteorder="little")
        fragment_number = sequence_control_raw & 0x000F        # bits 0-3
        sequence_number = (sequence_control_raw >> 4) & 0x0FFF  # bits 4-15

        offset = 24
        address4 = None

        # if this is a data or QoS data frame with both To DS and From DS set => 4 addresses
        if frame_type == 2 and to_ds and from_ds:
            if len(header_bytes) >= offset + 6:
                address4 = _format_mac(header_bytes[offset:offset+6])
                offset += 6

        # -----------------------------
        # QoS Control
        # -----------------------------
        qos_control_raw = None
        ht_control_raw = None

        # if type is Data and the subtype >= 8 => likely QoS capable
        if frame_type == 2 and subtype >= 8 and subtype <= 15:
            if len(header_bytes) >= offset + 2:
                qos_control_raw = int.from_bytes(header_bytes[offset:offset+2], byteorder="little")
                offset += 2

            if order_flag:
                if len(header_bytes) >= offset + 4:
                    # some references say 4 bytes, others 2, 802.11n says 4. We parse 4 here
                    ht_control_raw = header_bytes[offset:offset+4]
                    offset += 4

        frame_body = header_bytes[offset:]
        
        parsed_body = None
        if type_description == "Management" and subtype_description == "Probe Request":
            parsed_body = parse_probe_request(frame_body)

        return {
            # Protocol/Type/Subtype
            "protocol_version": protocol_version,
            "frame_type":       type_description,
            "subtype":          subtype_description,

            # Flags
            "to_ds":            to_ds,
            "from_ds":          from_ds,
            "more_frag":        more_frag,
            "retry":            retry,
            "power_mgmt":       power_mgmt,
            "more_data":        more_data,
            "protected_frame":  protected_frame,
            "order_flag":       order_flag,

            # Others
            "duration_id":      duration_id,

            # Addresses
            "address1": address1,
            "address2": address2,
            "address3": address3,
            "address4": address4,

            # Sequence
            "fragment_number":  fragment_number,
            "sequence_number":  sequence_number,

            # QoS/HT/Body
            "qos_control_raw":  qos_control_raw,
            "ht_control_raw":   ht_control_raw.hex() if ht_control_raw else None,
            "frame_body":       frame_body.hex()
        }

    except Exception as e:
        print(f"Error translating header: {e}")
        return None

def _format_mac(mac_bytes):
    if len(mac_bytes) < 6:
        return None
    return ":".join(f"{b:02x}" for b in mac_bytes)

def process_mac(mac):
    return mac.replace(":", "").upper()[:6]
oui_df = pd.read_csv("oui.csv")
oui_vendor_mapping = dict(zip(oui_df["Assignment"], oui_df["Organization Name"]))


client = clickhouse_connect.get_client(
    host='10.150.104.116',
    port=8123,
    username='monad',
    password='gDFtLN2rc8M7VxnTfbPqH6'
)

source_table = "monadcount.l2pk_v2"
parsed_table = "monadcount.l2pk_v2_struct"

create_sql = f"""
CREATE TABLE IF NOT EXISTS {parsed_table}
(
    id UUID,
    protocol_version UInt8,
    frame_type String,
    subtype String,
    to_ds UInt8,
    from_ds UInt8,
    more_frag UInt8,
    retry UInt8,
    power_mgmt UInt8,
    more_data UInt8,
    protected_frame UInt8,
    order_flag UInt8,

    duration_id UInt16,

    address1 String,
    address2 String,
    address3 String,
    address4 String,

    fragment_number UInt16,
    sequence_number UInt16,

    qos_control_raw UInt16,
    ht_control_raw String,
    frame_body String,

    vendor String
)
ENGINE = ReplacingMergeTree
ORDER BY id
"""

client.command(create_sql)

CHUNK_SIZE = 50_000
OFFSET = 113460000

while True:
    query = f"""
        SELECT id, header
        FROM {source_table}
        LIMIT {CHUNK_SIZE} OFFSET {OFFSET}
    """
    rows = client.query(query).named_results()
    if not rows:
        print("No more rows to process.")
        break

    insert_data = []
    for row in rows:
        row_id = row["id"]
        header_b64 = row["header"]

        decoded = decode_header(header_b64)
        parsed  = translate_header(decoded) if decoded else None
        if not parsed:
            continue

        frame_type_str = parsed["frame_type"]
        from_ds        = parsed["from_ds"]

        # Figure out where the source MAC lives
        if frame_type_str == "Data":
            if from_ds:
                source_mac = parsed["address3"]
            else:
                source_mac = parsed["address2"]
        else:
            source_mac = parsed["address2"]

        oui    = process_mac(source_mac or "")
        vendor = oui_vendor_mapping.get(oui, "Unknown")

        insert_data.append((
            row_id,
            parsed["protocol_version"],
            parsed["frame_type"],
            parsed["subtype"],
            parsed["to_ds"],
            parsed["from_ds"],
            parsed["more_frag"],
            parsed["retry"],
            parsed["power_mgmt"],
            parsed["more_data"],
            parsed["protected_frame"],
            parsed["order_flag"],

            parsed["duration_id"],

            parsed["address1"],
            parsed["address2"],
            parsed["address3"],
            parsed["address4"] if parsed["address4"] else "",

            parsed["fragment_number"],
            parsed["sequence_number"],

            parsed["qos_control_raw"],
            parsed["ht_control_raw"],
            parsed["frame_body"],

            vendor
        ))

    if not insert_data:
        print(f"No valid rows in chunk (offset={OFFSET}).")
        OFFSET += CHUNK_SIZE
        continue

    client.insert(
        parsed_table,
        insert_data,
        column_names=[
            "id",
            "protocol_version",
            "frame_type",
            "subtype",
            "to_ds",
            "from_ds",
            "more_frag",
            "retry",
            "power_mgmt",
            "more_data",
            "protected_frame",
            "order_flag",
            "duration_id",
            "address1",
            "address2",
            "address3",
            "address4",
            "fragment_number",
            "sequence_number",
            "qos_control_raw",
            "ht_control_raw",
            "frame_body",
            "vendor"
        ]
    )

    print(f"Inserted {len(insert_data)} decoded rows (offset={OFFSET}).")
    OFFSET += CHUNK_SIZE

print("Finished inserting!")
