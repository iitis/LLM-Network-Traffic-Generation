import json
from typing import List, Dict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler, LabelEncoder
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader

# -------------------------
# Config
# -------------------------
SEQ_LEN = None  # if None, uses full-length sequences (sliding window of full length -> single sequence)
BATCH_SIZE = 8
HIDDEN_DIM = 64
EPOCHS_AE = 1500
EPOCHS_ADV = 3000
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
SOFTPLUS_BETA = 1.0  # parameter for softplus if you want to tweak
INPUT_JSON = 'raw_data.json'  # input raw data file
OUTPUT_JSON = 'output.json'  # output generated data file
NO_OF_SEQ = 1  # number of sequences to generate

# -------------------------
# Load raw data from JSON file placed next to this script
# -------------------------
_data_path = Path(__file__).resolve().parent / INPUT_JSON
if not _data_path.exists():
    raise FileNotFoundError(f"Raw data file not found: {_data_path}")
with _data_path.open('r', encoding='utf-8') as _f:
    raw = json.load(_f)

if not isinstance(raw, list) or len(raw) == 0:
    raise ValueError("raw_data.json should contain a non-empty list of JSON records.")

# -------------------------
# Preprocessing: JSON -> DataFrame -> features
# -------------------------
def prepare_dataframe(raw_list: List[Dict]) -> pd.DataFrame:
    df = pd.DataFrame(raw_list)
    # ensure required columns exist
    required = {'time', 'length', 'src', 'dst', 'protocol', 'info'}
    if not required.issubset(df.columns):
        raise ValueError(f"Each record must contain columns: {required}")
    # convert numeric fields
    df['time'] = df['time'].astype(float)
    df['length'] = df['length'].astype(float)
    return df

df = prepare_dataframe(raw)

# compute delta t (Δt)
df = df.sort_values('time').reset_index(drop=True)
df['delta_t'] = df['time'].diff().fillna(0.0)  # first delta = 0

# categorical encoders
cat_cols = ['src', 'dst', 'protocol', 'info']
encoders = {}
for c in cat_cols:
    le = LabelEncoder()
    df[c + '_le'] = le.fit_transform(df[c].astype(str))
    encoders[c] = le

# One-hot encode categories (concatenated)
ohe = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
cat_matrix = ohe.fit_transform(df[[col + '_le' for col in cat_cols]])

# scaler for numeric columns (delta_t, length)
scaler = MinMaxScaler()
num_matrix = scaler.fit_transform(df[['delta_t', 'length']])

# final feature matrix (N x D)
X = np.hstack([num_matrix, cat_matrix]).astype(np.float32)
feature_dim = X.shape[1]

print("Prepared features shape:", X.shape)
print("OneHotEncoder categories sizes:", [len(c) for c in ohe.categories_])

# -------------------------
# Create sequences (sliding window)
# -------------------------
if SEQ_LEN is None:
    SEQ_LEN = len(raw)

def create_sequences(X: np.ndarray, seq_len: int) -> np.ndarray:
    seqs = []
    for i in range(0, len(X) - seq_len + 1):
        seqs.append(X[i:i+seq_len])
    return np.stack(seqs) if seqs else np.zeros((0, seq_len, X.shape[1]), dtype=np.float32)

seqs = create_sequences(X, SEQ_LEN)
if seqs.shape[0] == 0:
    raise ValueError("Not enough data to create a single sequence. Reduce SEQ_LEN or provide more data.")
print("Number of sequences:", len(seqs), "sequence shape:", seqs.shape)

# -------------------------
# PyTorch Dataset
# -------------------------
class SeqDataset(Dataset):
    def __init__(self, sequences):
        self.seq = torch.from_numpy(sequences)
    def __len__(self):
        return self.seq.shape[0]
    def __getitem__(self, idx):
        return self.seq[idx]

dataset = SeqDataset(seqs)
dataloader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True, drop_last=False)

# -------------------------
# Models
# -------------------------
hidden_dim = HIDDEN_DIM
device = DEVICE

class Embedder(nn.Module):
    def __init__(self, input_dim, hidden_dim):
        super().__init__()
        self.rnn = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, hidden_dim)
    def forward(self, x):
        h, _ = self.rnn(x)
        z = torch.tanh(self.fc(h))
        return z

class Recovery(nn.Module):
    """
    Recovery maps hidden-space sequence back to feature space.
    We apply Softplus only to numeric output columns (first two dims: delta_t, length)
    to ensure they are strictly non-negative and smooth.
    """
    def __init__(self, hidden_dim, output_dim, numeric_dims=2):
        super().__init__()
        self.rnn = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, output_dim)
        self.softplus = nn.Softplus(beta=SOFTPLUS_BETA)
        self.numeric_dims = numeric_dims

    def forward(self, z):
        h, _ = self.rnn(z)
        x_tilde = self.fc(h)  # shape (bs, seq_len, output_dim)
        # apply softplus only to numeric columns (delta_t, length)
        if self.numeric_dims > 0:
            num_part = x_tilde[:, :, :self.numeric_dims]
            cat_part = x_tilde[:, :, self.numeric_dims:]
            num_pos = self.softplus(num_part)
            x_tilde = torch.cat([num_pos, cat_part], dim=2)
        return x_tilde

class Generator(nn.Module):
    def __init__(self, noise_dim, hidden_dim):
        super().__init__()
        self.rnn = nn.LSTM(noise_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, hidden_dim)
    def forward(self, z0):
        h, _ = self.rnn(z0)
        h = torch.tanh(self.fc(h))
        return h  # synthetic hidden-space sequence

class Supervisor(nn.Module):
    def __init__(self, hidden_dim):
        super().__init__()
        self.rnn = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, hidden_dim)
    def forward(self, h):
        s, _ = self.rnn(h)
        return torch.tanh(self.fc(s))

class Discriminator(nn.Module):
    def __init__(self, hidden_dim):
        super().__init__()
        self.rnn = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)
    def forward(self, h):
        y, _ = self.rnn(h)
        y = self.fc(y)
        # average over time steps
        return torch.sigmoid(y.mean(dim=1))

# instantiate
embedder = Embedder(feature_dim, hidden_dim).to(device)
recovery = Recovery(hidden_dim, feature_dim, numeric_dims=2).to(device)
generator = Generator(noise_dim=feature_dim, hidden_dim=hidden_dim).to(device)
supervisor = Supervisor(hidden_dim).to(device)
discriminator = Discriminator(hidden_dim).to(device)

# optimizers
e_opt = torch.optim.Adam(list(embedder.parameters()) + list(recovery.parameters()), lr=1e-3)
g_opt = torch.optim.Adam(list(generator.parameters()) + list(supervisor.parameters()), lr=1e-3)
d_opt = torch.optim.Adam(discriminator.parameters(), lr=1e-3)

mse = nn.MSELoss()

# -------------------------
# Training - phase 1: embedder + recovery (autoencoder)
# -------------------------
print("Training autoencoder (embedder + recovery)...")
for ep in range(EPOCHS_AE):
    epoch_loss = 0.0
    for batch in dataloader:
        batch = batch.to(device)
        z = embedder(batch)
        x_tilde = recovery(z)
        loss = mse(x_tilde, batch)
        e_opt.zero_grad()
        loss.backward()
        e_opt.step()
        epoch_loss += loss.item()
    if (ep+1) % 100 == 0 or ep == 0:
        print(f"AE epoch {ep+1}/{EPOCHS_AE}, loss={epoch_loss/len(dataloader):.6f}")

# -------------------------
# Training - phase 2: adversarial + supervisor
# -------------------------
print("Training adversarial (generator, supervisor, discriminator)...")
for ep in range(EPOCHS_ADV):
    for batch in dataloader:
        batch = batch.to(device)
        bs, sl, fd = batch.shape

        # === discriminator step ===
        with torch.no_grad():
            h_real = embedder(batch)  # shape (bs, sl, hidden)
        z_noise = torch.randn(bs, sl, feature_dim, device=device)
        h_fake = generator(z_noise)
        h_fake_sup = supervisor(h_fake)

        y_real = discriminator(h_real)
        y_fake = discriminator(h_fake_sup.detach())

        d_loss = -torch.log(y_real + 1e-8).mean() - torch.log(1 - y_fake + 1e-8).mean()

        d_opt.zero_grad()
        d_loss.backward()
        d_opt.step()

        # === generator + supervisor step ===
        z_noise = torch.randn(bs, sl, feature_dim, device=device)
        h_fake = generator(z_noise)
        h_fake_sup = supervisor(h_fake)
        y_fake = discriminator(h_fake_sup)
        g_loss_adv = -torch.log(y_fake + 1e-8).mean()

        with torch.no_grad():
            h_real = embedder(batch)
        g_loss_sup = mse(h_fake_sup, h_real)

        g_loss = g_loss_adv + 100 * g_loss_sup

        g_opt.zero_grad()
        g_loss.backward()
        g_opt.step()

    if (ep+1) % 200 == 0 or ep == 0:
        print(f"ADV epoch {ep+1}/{EPOCHS_ADV}, d_loss={d_loss.item():.6f}, g_loss={g_loss.item():.6f}")

print("Training finished.")

# -------------------------
# Generation
# -------------------------
def generate_sequences(n_seq: int, seq_len: int):
    generator.eval(); supervisor.eval(); recovery.eval()
    with torch.no_grad():
        z_noise = torch.randn(n_seq, seq_len, feature_dim, device=device)
        h_fake = generator(z_noise)
        h_fake_sup = supervisor(h_fake)
        x_fake = recovery(h_fake_sup)  # in feature space (normalized)
        return x_fake.cpu().numpy()

fake_seqs = generate_sequences(NO_OF_SEQ, int(SEQ_LEN))
print("Generated fake sequences shape:", fake_seqs.shape)

# -------------------------
# Denormalize and convert back to JSON
# -------------------------
def decode_sequence(seq_norm):
    # seq_norm shape (seq_len, feature_dim)
    # split: first two columns were num (delta_t, length), rest are ohe cats
    num = seq_norm[:, :2]
    cats = seq_norm[:, 2:]
    # denormalize numeric
    num_denorm = scaler.inverse_transform(num)
    delta_ts = num_denorm[:, 0]
    lengths = num_denorm[:, 1].round().astype(int)

    # enforce non-negativity as final safety net
    delta_ts = np.clip(delta_ts, 0.0, None)
    lengths = np.clip(lengths, 0, None).astype(int)

    # decode categories by slicing according to ohe.categories_
    cat_values_per_col = []
    start = 0
    for i, categories in enumerate(ohe.categories_):
        k = len(categories)
        col_onehot = cats[:, start:start + k]
        # handle potential numerical instability by argmax
        idxs = np.argmax(col_onehot, axis=1)
        # idxs correspond to label-encoded integers -> invert using LabelEncoder
        labels = encoders[cat_cols[i]].inverse_transform(idxs)
        cat_values_per_col.append(labels)
        start += k

    # reconstruct JSON per timestep
    seq_jsons = []
    # reconstruct timestamps from delta_t; start at the original first time OR 0.0
    # choose start_time from original data's first time for realism
    start_time = float(df['time'].iloc[0]) if 'time' in df.columns else 0.0
    t = start_time
    for i in range(seq_norm.shape[0]):
        t += float(delta_ts[i])
        j = {
            'time': float(round(t, 6)),
            'length': int(lengths[i]),
            'src': str(cat_values_per_col[0][i]),
            'dst': str(cat_values_per_col[1][i]),
            'protocol': str(cat_values_per_col[2][i]),
            'info': str(cat_values_per_col[3][i])
        }
        seq_jsons.append(j)
    return seq_jsons

# show generated JSONs and save to output file
output_path = Path(__file__).resolve().parent / OUTPUT_JSON
all_generated = []
for i, seq in enumerate(fake_seqs, start=1):
    seq_jsons = decode_sequence(seq)
    print(f"\nGenerated sequence #{i}:")
    print(json.dumps(seq_jsons, indent=2))
    all_generated.append(seq_jsons)

# write all generated sequences to file
with output_path.open('w', encoding='utf-8') as f:
    json.dump(all_generated, f, ensure_ascii=False, indent=2)
print(f"Saved {len(all_generated)} generated sequence(s) to {output_path}")

def average_packet_length(packets):
    # support both: a) list of packets, b) list of sequences (each a list of packets)
    if isinstance(packets, list) and len(packets) > 0 and isinstance(packets[0], list):
        packets = packets[0]
    if not packets:
        return 0.0, 0, 0
    lengths = []
    for packet in packets:
        # If packet is a dict and has numeric 'length' field, use it
        if isinstance(packet, dict) and 'length' in packet:
            try:
                lengths.append(int(packet['length']))
            except Exception:
                try:
                    lengths.append(int(float(packet['length'])))
                except Exception:
                    lengths.append(len(json.dumps(packet)))
        else:
            # Fallback to JSON string length
            lengths.append(len(json.dumps(packet)))
    avg = sum(lengths) / len(lengths)
    return avg, min(lengths), max(lengths)


avg_len, min_len, max_len = average_packet_length(all_generated)
print("Average characters per packet:", avg_len)
print("Min packet length:", min_len)
print("Max packet length:", max_len)

num_packets = len(all_generated)
print("Number of packets in sample:", num_packets)

minimum_total_packet_length = num_packets * min_len
print("Estimated minimum characters for real traffic:", minimum_total_packet_length)

average_total_packet_length = num_packets * avg_len
print("Estimated total characters for real traffic:", average_total_packet_length)

maximum_total_packet_length = num_packets * max_len
print("Estimated maximum characters for real traffic:", maximum_total_packet_length)

number_of_char = average_total_packet_length + 1000  # Extra buffer for safety
print("Number of characters to generate is calculated as:", int(number_of_char))
