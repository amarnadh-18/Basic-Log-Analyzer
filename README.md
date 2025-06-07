# Basic Log Analyzer

A Python-based log analysis tool that detects suspicious activity in system log files using pattern matching and anomaly detection techniques.

## 🔍 Features

- 📂 Analyze multiple log files from a selected directory  
- 🧠 Detect anomalies using Isolation Forest (ML)  
- 🔎 Custom pattern matching with regular expressions  
- 📊 Generate reports and visualizations for insights  
- 🛡️ Suggestions for potential security remedies  

## 🛠️ Tech Stack

- **Language:** Python  
- **GUI:** Tkinter  
- **ML Model:** Isolation Forest (`scikit-learn`)  
- **Data Handling:** `pandas`, `re`, `json`  

## 📁 Project Structure

```
Log Analyzer/
├── Log Samples/ # Sample log files
├── output/ # Analysis output files
├── main.py # Main GUI application
├── log_analyzer_configure.json # Configuration and custom regex patterns
├── requirements.txt # Python dependencies
└── LICENSE / README.md

```

---


## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/amarnadh-18/Basic-Log-Analyzer.git
cd Basic-Log-Analyzer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Application

```bash
python3 main.py
```

---

## 🧪 Sample Logs

Sample logs are available in the `Log Samples/` directory. You can add your own `.log` files there.

## 📌 Customization

Edit `log_analyzer_configure.json` to:

- Add your own regex patterns  
- Define severity levels and descriptions  

---

> Developed with 🔐 by [@amarnadh-18](https://github.com/amarnadh-18) and [@Taraka21](https://github.com/Taraka21)


