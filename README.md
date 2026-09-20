# 🔍 Cryptographic Hash Identifier CLI

A modular, architecture-focused Python identification engine and CLI tool designed to analyze and detect cryptographic hash formats. Built using multi-layered heuristic rules, structural validation, and character-set evaluation.

---

## 📸 Key Features

* **Multi-Layered Detection Engine:** Evaluates input strings using exact PHC/Password prefix matches, cryptographic salt structures, and charset/length heuristics.
* **Rich Terminal UI:** Interactive and argument-driven CLI output formatted with tables and confidence badges powered by `rich` and `argparse`.
* **Clean Architecture:** Strict separation of concerns between the core algorithm processing logic (`src/hash_identifier.py`) and the presentation layer (`src/cli.py`).
* **Test-Driven Design:** Fully covered unit test suite built with `pytest` for robust code validation.

---

## 📁 Project Structure

```text
hash-identifier/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── docs/
│   ├── 01-Hash Concepts.md
│   ├── 02-Identification signals in hash analysis.md
│   ├── 03-Salts in Cryptographic Hashing.md
├── src/
│   ├── __init__.py
│   ├── hash_identifier.py
│   └── cli.py
└── test/
    ├── __init__.py
    └── test_hash_identifier.py

```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/rotoyy/hash-identifier.git
cd hash-identifier

```

### 2. Set up the virtual environment

```bash
python -m venv .venv

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# On macOS/Linux:
source .venv/bin/activate

```

### 3. Install dependencies

```bash
pip install -r requirements.txt

```

---

## 💡 Usage

### CLI Parameter Mode

Pass the hash string directly as a parameter for quick analysis:

```bash
python -m src.cli -s "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK"

```

### Interactive Mode

Launch the tool without arguments to receive an interactive prompt:

```bash
python -m src.cli

```

---

## 🧪 Running Tests

Execute the automated test suite using `pytest` from the root directory:

```bash
pytest

```

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
