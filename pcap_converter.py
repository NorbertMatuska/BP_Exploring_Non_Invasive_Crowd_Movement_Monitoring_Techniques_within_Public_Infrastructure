import pandas as pd
from pathlib import Path
from scapy.all import rdpcap, Dot11
import hmac, hashlib
from tqdm import tqdm

_ANON_KEY = bytes.fromhex(
    "d2c5f7b5c1a3e9d0ed9b2f0aff3c4eaab8f6c1a92463d4e17f5c9efa2e5be83c"
)

def anon_mac(mac: str, n_bytes: int = 8) -> str:
    raw = hmac.new(_ANON_KEY, mac.encode(), hashlib.sha256).digest()
    return raw[:n_bytes].hex()

def extract_frames(pcap_path: Path):
    """Yield (relative_time, src_mac) tuples from one pcap file."""
    pkts = rdpcap(str(pcap_path), count=-1)
    if not pkts:
        return
    t0 = pkts[0].time
    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        dot11 = p[Dot11]
        if dot11.type not in (0, 2):
            continue
        mac = dot11.addr2
        if mac is None or mac.lower().startswith(("ff:ff", "01:00")):
            continue
        mac = anon_mac(mac.lower())
        yield p.time, mac.lower()

def join_pcaps_and_save(run_dir: Path):
    """Join all pcaps in run_dir and save as events.csv."""
    pcap_files = list(run_dir.glob("*.pcap"))
    if not pcap_files:
        print(f"[SKIP] No pcaps found in {run_dir}")
        return
    records = []
    t0_global = None

    for pcap in tqdm(sorted(pcap_files), desc=f"Parsing {run_dir}"):
        for abs_ts, mac in extract_frames(pcap):
            records.append((abs_ts, mac))
            if t0_global is None or abs_ts < t0_global:
                t0_global = abs_ts

    if not records:
        print(f"[SKIP] No usable frames in {run_dir}")
        return

    df = pd.DataFrame(records, columns=["abs_time", "mac"])
    df["time"] = df["abs_time"] - t0_global
    df.drop(columns="abs_time", inplace=True)
    df.sort_values("time", inplace=True)
    df.reset_index(drop=True, inplace=True)

    out_csv = run_dir / "events.csv"
    df.to_csv(out_csv, index=False)
    print(f"[OK] Saved {len(df)} events to {out_csv}")

def process_all_runs(data_root: Path):
    """Walk data/ folder and process every run."""
    for scenario_dir in data_root.iterdir():
        if not scenario_dir.is_dir():
            continue
        for crowd_dir in scenario_dir.iterdir():
            if not crowd_dir.is_dir():
                continue
            for run_dir in crowd_dir.iterdir():
                if not run_dir.is_dir():
                    continue
                out_csv = run_dir / "events.csv"
                if out_csv.exists():
                    print(f"[SKIP] Already exists: {out_csv}")
                    continue
                join_pcaps_and_save(run_dir)

if __name__ == "__main__":
    DATA_ROOT = Path("data")
    process_all_runs(DATA_ROOT)
