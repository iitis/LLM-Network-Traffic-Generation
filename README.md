# Network Traffic Generation by Large Language Models (LLMs)

This repository presents a novel approach for generating **realistic network traffic** using **Large Language Models (LLMs)**, specifically **OpenAI’s GPT-4.1** and **GPT-5**.  

Our method, called the **Large Language Model Network Traffic Generator (LLM-NTG)**, aims to bridge the gap between **realistic traffic generation** and the **expressive capabilities of LLMs**.  
We employ a few-shot learning framework combined with a **human-in-the-loop feedback mechanism**, where generated traffic is continuously evaluated and refined.

---

## 📂 Repository Structure

### 1. `Datasets/`
Contains datasets required for traffic generation:
- **One-way** and **two-way traffic datasets**.
- **Sample inputs** in `.json`, `.pcapng`, and `.csv` formats for traffic generation.

---

### 2. `GPT-4.1/`
Experiments performed with **GPT-4.1**.  
This folder has two subfolders: `Experiment_1/` and `Experiment_2/`.

Each experiment includes:
- **`Exp1_Sample_Packets_Extraction.ipynb`**  
  Extracts traffic data from the dataset and prepares **sample packets** for generation.
- **`Exp1_Traffic_Generation_gpt4.1.ipynb`**  
  Generates synthetic traffic and saves the output as `.json` files.
- **`Exp1_Statistics_of_Generated_Traffics_gpt4.1.ipynb`**  
  Computes statistics of the generated traffic.

(`Experiment_2/` follows the same structure.)

---

### 3. `GPT-5/`
Experiments performed with **GPT-5**.  
This folder also has `Experiment_1/` and `Experiment_2/`.

Since the **same input samples** are used as in GPT-4.1, there is no extraction notebook here.  
Each experiment includes:
- **`Exp1_Traffic_Generation_gpt5.ipynb`**  
  Generates synthetic traffic with GPT-5.
- **`Exp1_Statistics_of_Generated_Traffics_gpt5.ipynb`**  
  Computes statistics of the generated traffic.

(`Experiment_2/` follows the same structure.)

---

### 4. `Generated_Traffic/`
Contains the **generated traffic outputs** in `.json` format.  
- Each experiment’s results are stored here.  
- The `Results/` subfolder contains details such as:
  - **Token usage**
  - **Computation time**

---

### 5. `pcap_converter.py`
A transformation script that converts generated `.json` traffic files into **`.pcap` format**, enabling further analysis with standard network traffic tools (e.g., Wireshark).

---

## 🚀 Usage
1. Explore the **datasets** under `Datasets/`.  
2. Run the notebooks in `GPT-4.1/` or `GPT-5/` for traffic generation.  
3. Generated traffic will be saved under `Generated_Traffic/`.  
4. Optionally, convert `.json` traffic files into `.pcap` format using:
   ```bash
   python pcap_converter.py input.json output.pcap
