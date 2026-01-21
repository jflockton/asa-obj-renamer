# ASA Object Renamer

A safe, deterministic utility for **renaming legacy Cisco ASA `object network` entries** and updating all references in configuration files.

This tool is designed for **one-time or batch clean-up** of ASA configs where object names are inconsistent, unclear, or pre-standardisation.

---

## 🚨 Safety First: Core Rules

This script enforces the following **non-negotiable invariants**:

### 🔒 Objects starting with `obj-` are **never touched**
If an object name starts with:

```
obj-
```

then it is treated as **authoritative and immutable**.

That means:
- ❌ No renaming
- ❌ No normalisation
- ❌ No reference replacement
- ❌ No flags or overrides

This makes the script **idempotent** and safe to re-run.

---

## 🧠 What the Script Does

For each `object network` block that **does not** start with `obj-`, the script:

1. Inspects the object definition to determine its type:
   - `host`
   - `subnet`
   - `range`

2. Classifies the address into a scope:
   - **INT**:  
     `10.0.0.0/8`, `192.168.0.0/16`
   - **DMZ**:  
     `172.0.0.0/8`
   - **EXT**:  
     Anything else

3. Builds a new canonical name using a strict format:

| Type   | Prefix Example |
|------|----------------|
| Host | `obj-int-host-` |
| Net  | `obj-dmz-net-`  |
| Range | `obj-ext-range-` |

4. Normalises the resulting name:
   - Lowercase
   - Dots → underscores
   - Collapses repeated underscores
   - Preserves trailing digit blocks
   - Removes redundant `network_` and `host-host` artifacts

5. Updates **all references** to the object name across the file using **safe token-based replacement**.

---

## 🗂️ What It Does NOT Do

- ❌ Does not modify `object-group network`
- ❌ Does not touch service objects
- ❌ Does not parse NAT logic
- ❌ Does not handle IPv6
- ❌ Does not rewrite already-standardised objects

This is intentional. The tool is **surgical**, not a general ASA refactoring engine.

---

## 📁 Expected File Layout

Recommended structure:

```
asa-obj-renamer/
├── object-rename.py
├── configs/
│   ├── fw1-ASA.asa
│   ├── fw2-ASA.asa
│   └── fw3-ASA.asa
└── out/
```

---

## ▶️ How to Run

### Basic usage (default)
Runs against `*.asa` files in the **current directory**:

```bash
python3 object-rename.py
```

### Recommended usage (separate configs)
```bash
python3 object-rename.py --glob "configs/*.asa"
```

### Dry run (no config written)
```bash
python3 object-rename.py --glob "configs/*.asa" --dry-run
```

---

## 📤 Output Files

For each input file `X.asa`, the script produces:

| File | Purpose |
|----|-------|
| `out/X_RENAMED.asa` | Updated ASA config |
| `out/chgs-X.asa.log` | Full audit log |
| *(dry-run only)* | No config written |

---

## 🧪 Example Transformation

### Input
```asa
object network DC01
 host 10.10.1.5
```

### Output
```asa
object network obj-int-host-dc01
 host 10.10.1.5
```

---

## 🛠️ Requirements

- Python **3.8+**
- Standard library only
- No Poetry
- No virtualenv required
