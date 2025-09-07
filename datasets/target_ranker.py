import pandas as pd
import numpy as np

# Match structure of the provided dataset
np.random.seed(42)
num_samples = 1000  # adjust as needed

synthetic_data = pd.DataFrame({
    "open_ports_count": np.random.randint(0, 20, size=num_samples),
    "has_smb": np.random.choice([True, False], size=num_samples),
    "has_http": np.random.choice([True, False], size=num_samples),
    "has_rdp": np.random.choice([True, False], size=num_samples),
    "has_sql": np.random.choice([True, False], size=num_samples),
    "has_ftp": np.random.choice([True, False], size=num_samples),
    "os_windows": np.random.choice([True, False], size=num_samples),
    "os_linux": np.random.choice([True, False], size=num_samples),
    "port_445_open": np.random.choice([True, False], size=num_samples),
    "port_3389_open": np.random.choice([True, False], size=num_samples),
    "port_21_open": np.random.choice([True, False], size=num_samples),
    "port_22_open": np.random.choice([True, False], size=num_samples),
    "port_80_open": np.random.choice([True, False], size=num_samples),
    "port_443_open": np.random.choice([True, False], size=num_samples),
})

# --- Label heuristic similar to original ---
synthetic_data["label"] = (
    (synthetic_data["has_smb"] & synthetic_data["port_445_open"]) |
    (synthetic_data["has_rdp"] & synthetic_data["port_3389_open"]) |
    (synthetic_data["has_http"] & synthetic_data["port_80_open"]) |
    (synthetic_data["open_ports_count"] > 8)  # tuned to mimic original
).astype(int)

# Save to CSV
synthetic_data.to_csv("synthetic_training_data.csv", index=False)

print("✅ synthetic_training_data.csv generated with same structure as original")
