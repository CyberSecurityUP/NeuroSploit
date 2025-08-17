# 🧠 NeuroSploit

**NeuroSploit** is an AI-powered offensive security agent designed to automate penetration testing tasks.  
It is built on **ChatGPT-5** (with support for other LLMs in the future) and aims to fully solve the **Damn Vulnerable Web Application (DVWA)** across all difficulty levels.

The goal of NeuroSploit is to provide an intelligent, modular, and automated assistant for pentesters, researchers, and Red Team operators.

---

## ⚡ Features

- AI-driven exploitation using **prompt-engineered reasoning**.  
- Modular skill system (e.g., `xss_dom_low`, `sqli_blind_high`).  
- Support for **multiple LLM backends** (default: ChatGPT-5).  
- Designed to **autonomously solve 100% of DVWA**.  
- Extensible for real-world pentesting labs.

---

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourname/NeuroSploit.git
cd NeuroSploit
````

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🐐 Setting up DVWA

To test NeuroSploit locally, you need DVWA (Damn Vulnerable Web Application).

### 1. Install DVWA using Docker

```bash
git clone https://github.com/digininja/DVWA.git
cd DVWA
docker build -t dvwa .
docker run -it -p 80:80 dvwa
```

DVWA should now be available at:
👉 `http://localhost/DVWA`

Default credentials:

* **Username:** `admin`
* **Password:** `password`

### 2. Configure DVWA

1. Log in at `http://localhost/DVWA/login.php`
2. Navigate to **Setup / Reset Database**
3. Click **Create / Reset Database**
4. Set the **DVWA Security Level** (Low, Medium, High, Impossible) from the **DVWA Security** tab.

---

## 🚀 Usage

Example command:

```bash
python3 -m src.run --target 'http://localhost/DVWA' --skill xss_dom_low
```

This tells **NeuroSploit** to:

* Use the AI agent backend (`ChatGPT-5` by default).
* Target `http://localhost/DVWA`.
* Execute the **XSS DOM-based (Low security)** exploitation module.

---

## 📂 Project Structure

```
NeuroSploit/
│── src/
│   ├── run.py          # Main entrypoint
│   ├── agents/         # AI agents
│   ├── skills/         # Exploitation modules (XSS, SQLi, CSRF, etc.)
│   └── utils/          # Helpers (HTTP requests, parsing, logging)
│
│── requirements.txt
│── README.md
```

---

## Offline LLM Support (LLaMA)

```
curl -fsSL https://ollama.com/install.sh | sh
ollama list
ollama serve
ollama pull llama3.2:1b
export MODEL_PROVIDER=ollama
export LLAMA_MODEL=llama3.2:1b
export LLAMA_BASE_URL=http://localhost:11434
curl -s http://localhost:11434/api/generate \
 -d '{"model":"llama3.1","prompt":"Return JSON: {\"ok\":true}","stream":false,"options":{"temperature":0}}'
```

---

## 🔮 Roadmap

* [ ] Add support for **SQL Injection automation**.
* [ ] Expand to **other vulnerable labs** (bWAPP, Juice Shop, VulnHub).
* [ ] Integration with **Red Team C2 frameworks**.
* [X] Offline LLM support (LLaMA, Falcon).

---


## ⚠️ Disclaimer

This project is intended **for educational and research purposes only**.
Do **not** use it against systems without **explicit permission**.

Use responsibly. 🛡️

