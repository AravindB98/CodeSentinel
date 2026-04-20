"""
Synthetic evaluation sample generator.

Produces (vulnerable_code, safe_variant, ground_truth_label) triples using
the LLM. In mock mode, uses a curated template library so the pipeline
still produces diverse output offline.

Every generated sample is subsequently verified by synth.verify, which
uses a separate prompt with NO shared context to avoid the generator
gaming the verifier.

Usage:
    python -m synth.generate --count 20 --out eval/datasets/synthetic_suite.json
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import re
from pathlib import Path
from typing import Dict, List, Optional

from utils.llm_client import get_llm

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)


# Target CWE coverage for synthetic generation.
TARGET_CWES = [
    ("CWE-89", "SQL Injection", "python"),
    ("CWE-89", "SQL Injection", "javascript"),
    ("CWE-89", "SQL Injection", "java"),
    ("CWE-502", "Deserialization of Untrusted Data", "python"),
    ("CWE-502", "Deserialization of Untrusted Data", "java"),
    ("CWE-78", "OS Command Injection", "python"),
    ("CWE-78", "OS Command Injection", "javascript"),
    ("CWE-94", "Code Injection", "python"),
    ("CWE-79", "Cross-Site Scripting", "javascript"),
    ("CWE-295", "Improper Certificate Validation", "python"),
    ("CWE-327", "Broken Cryptographic Algorithm", "python"),
    ("CWE-798", "Hardcoded Credentials", "python"),
    ("CWE-611", "XML External Entities", "java"),
    ("CWE-22", "Path Traversal", "python"),
    ("CWE-915", "Prototype Pollution", "javascript"),
]


GENERATOR_SYSTEM_PROMPT = """You are a synthetic data generator for a code-review system.
Your job is to produce ONE realistic code sample for each request.

Output a single JSON object with these fields:
- vulnerable_code: realistic code (5-25 lines) that exhibits the specified weakness
- safe_variant: the same general structure, with the weakness fixed
- explanation: one sentence describing the vulnerability and the fix

Rules:
- Use realistic variable names, typical frameworks (Flask, Express, Spring), and surrounding context.
- Do NOT include real credentials, real domains, or real exploit payloads.
- Keep code self-contained and runnable-looking.
- Return JSON only, no prose, no markdown fences.
"""


# --- Template library for mock mode ---

TEMPLATES: Dict[str, Dict[str, str]] = {
    ("CWE-89", "python"): {
        "vulnerable": (
            "import sqlite3\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/search\")\n"
            "def search():\n"
            "    term = request.args.get(\"q\", \"\")\n"
            "    conn = sqlite3.connect(\"products.db\")\n"
            "    cur = conn.cursor()\n"
            "    cur.execute(f\"SELECT * FROM products WHERE name LIKE '%{term}%'\")\n"
            "    return {{\"results\": cur.fetchall()}}\n"
        ),
        "safe": (
            "import sqlite3\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/search\")\n"
            "def search():\n"
            "    term = request.args.get(\"q\", \"\")\n"
            "    conn = sqlite3.connect(\"products.db\")\n"
            "    cur = conn.cursor()\n"
            "    cur.execute(\"SELECT * FROM products WHERE name LIKE ?\", (f\"%{{term}}%\",))\n"
            "    return {{\"results\": cur.fetchall()}}\n"
        ),
        "vuln_lines": [9],
        "explanation": "User-supplied term is concatenated into SQL via f-string; parameterize.",
    },
    ("CWE-89", "javascript"): {
        "vulnerable": (
            "const express = require('express');\n"
            "const mysql = require('mysql');\n"
            "const app = express();\n"
            "const db = mysql.createConnection({host: 'localhost'});\n\n"
            "app.get('/order', (req, res) => {\n"
            "  const id = req.query.id;\n"
            "  db.query(`SELECT * FROM orders WHERE id = ${id}`, (err, rows) => {\n"
            "    res.json(rows);\n"
            "  });\n"
            "});\n"
        ),
        "safe": (
            "const express = require('express');\n"
            "const mysql = require('mysql');\n"
            "const app = express();\n"
            "const db = mysql.createConnection({host: 'localhost'});\n\n"
            "app.get('/order', (req, res) => {\n"
            "  const id = req.query.id;\n"
            "  db.query('SELECT * FROM orders WHERE id = ?', [id], (err, rows) => {\n"
            "    res.json(rows);\n"
            "  });\n"
            "});\n"
        ),
        "vuln_lines": [8],
        "explanation": "Template literal interpolates user input into SQL; use parameterized query.",
    },
    ("CWE-89", "java"): {
        "vulnerable": (
            "import java.sql.*;\n\n"
            "public class Lookup {\n"
            "    public static ResultSet find(Connection conn, String userId) throws SQLException {\n"
            "        Statement stmt = conn.createStatement();\n"
            "        return stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + userId);\n"
            "    }\n"
            "}\n"
        ),
        "safe": (
            "import java.sql.*;\n\n"
            "public class Lookup {\n"
            "    public static ResultSet find(Connection conn, String userId) throws SQLException {\n"
            "        PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
            "        ps.setString(1, userId);\n"
            "        return ps.executeQuery();\n"
            "    }\n"
            "}\n"
        ),
        "vuln_lines": [6],
        "explanation": "String concatenation builds SQL; switch to PreparedStatement with placeholders.",
    },
    ("CWE-502", "python"): {
        "vulnerable": (
            "import pickle\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/state\", methods=[\"POST\"])\n"
            "def restore_state():\n"
            "    state = pickle.loads(request.data)\n"
            "    return {\"loaded\": bool(state)}\n"
        ),
        "safe": (
            "import json\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/state\", methods=[\"POST\"])\n"
            "def restore_state():\n"
            "    state = json.loads(request.data)\n"
            "    return {\"loaded\": bool(state)}\n"
        ),
        "vuln_lines": [7],
        "explanation": "pickle.loads on request data is RCE; use json.loads with a schema.",
    },
    ("CWE-502", "java"): {
        "vulnerable": (
            "import java.io.*;\n\n"
            "public class Sessions {\n"
            "    public Object restore(InputStream in) throws IOException, ClassNotFoundException {\n"
            "        ObjectInputStream ois = new ObjectInputStream(in);\n"
            "        return ois.readObject();\n"
            "    }\n"
            "}\n"
        ),
        "safe": (
            "import com.fasterxml.jackson.databind.ObjectMapper;\n"
            "import java.io.*;\n\n"
            "public class Sessions {\n"
            "    public SessionDto restore(InputStream in) throws IOException {\n"
            "        return new ObjectMapper().readValue(in, SessionDto.class);\n"
            "    }\n"
            "}\n"
        ),
        "vuln_lines": [6],
        "explanation": "ObjectInputStream.readObject on untrusted streams enables deserialization RCE.",
    },
    ("CWE-78", "python"): {
        "vulnerable": (
            "import subprocess\n"
            "from flask import request\n\n"
            "def tail_log():\n"
            "    logfile = request.args.get(\"file\")\n"
            "    return subprocess.check_output(f\"tail -n 50 {logfile}\", shell=True)\n"
        ),
        "safe": (
            "import subprocess\n"
            "from pathlib import Path\n"
            "from flask import request\n\n"
            "def tail_log():\n"
            "    logfile = request.args.get(\"file\", \"\")\n"
            "    safe_base = Path(\"/var/log\").resolve()\n"
            "    target = (safe_base / logfile).resolve()\n"
            "    if not target.is_relative_to(safe_base):\n"
            "        return {\"error\": \"invalid path\"}, 400\n"
            "    return subprocess.check_output([\"tail\", \"-n\", \"50\", str(target)])\n"
        ),
        "vuln_lines": [6],
        "explanation": "shell=True with user-controlled path allows command injection.",
    },
    ("CWE-78", "javascript"): {
        "vulnerable": (
            "const { exec } = require('child_process');\n\n"
            "app.get('/ping', (req, res) => {\n"
            "  const host = req.query.host;\n"
            "  exec(`ping -c 1 ${host}`, (err, stdout) => {\n"
            "    res.send(stdout);\n"
            "  });\n"
            "});\n"
        ),
        "safe": (
            "const { execFile } = require('child_process');\n\n"
            "app.get('/ping', (req, res) => {\n"
            "  const host = req.query.host;\n"
            "  if (!/^[A-Za-z0-9.-]+$/.test(host || '')) return res.status(400).send('bad host');\n"
            "  execFile('ping', ['-c', '1', host], (err, stdout) => {\n"
            "    res.send(stdout);\n"
            "  });\n"
            "});\n"
        ),
        "vuln_lines": [5],
        "explanation": "exec with template literal interpolates user input into a shell command.",
    },
    ("CWE-94", "python"): {
        "vulnerable": (
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/calc\")\n"
            "def calc():\n"
            "    expr = request.args.get(\"expr\", \"\")\n"
            "    return {\"result\": eval(expr)}\n"
        ),
        "safe": (
            "from flask import Flask, request\n"
            "from simpleeval import simple_eval\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/calc\")\n"
            "def calc():\n"
            "    expr = request.args.get(\"expr\", \"\")\n"
            "    return {\"result\": simple_eval(expr)}\n"
        ),
        "vuln_lines": [7],
        "explanation": "eval on user input is RCE; use a sandboxed evaluator like simpleeval.",
    },
    ("CWE-79", "javascript"): {
        "vulnerable": (
            "document.getElementById('welcome').innerHTML =\n"
            "  'Hello, ' + new URLSearchParams(location.search).get('name');\n"
        ),
        "safe": (
            "document.getElementById('welcome').textContent =\n"
            "  'Hello, ' + new URLSearchParams(location.search).get('name');\n"
        ),
        "vuln_lines": [1],
        "explanation": "innerHTML with URL-derived content is reflected XSS; use textContent.",
    },
    ("CWE-295", "python"): {
        "vulnerable": (
            "import requests\n\n"
            "def get_upstream(url):\n"
            "    return requests.get(url, verify=False).json()\n"
        ),
        "safe": (
            "import requests\n\n"
            "def get_upstream(url):\n"
            "    return requests.get(url).json()\n"
        ),
        "vuln_lines": [4],
        "explanation": "verify=False disables TLS verification; remove it.",
    },
    ("CWE-327", "python"): {
        "vulnerable": (
            "import hashlib\n\n"
            "def store_password(username, password):\n"
            "    digest = hashlib.md5(password.encode()).hexdigest()\n"
            "    save_user(username, digest)\n"
        ),
        "safe": (
            "import bcrypt\n\n"
            "def store_password(username, password):\n"
            "    digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()\n"
            "    save_user(username, digest)\n"
        ),
        "vuln_lines": [4],
        "explanation": "MD5 is a broken password hash; use bcrypt or argon2.",
    },
    ("CWE-798", "python"): {
        "vulnerable": (
            "import requests\n\n"
            "API_KEY = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n\n"
            "def get(url):\n"
            "    return requests.get(url, headers={\"Authorization\": f\"Bearer {API_KEY}\"})\n"
        ),
        "safe": (
            "import os, requests\n\n"
            "API_KEY = os.environ[\"UPSTREAM_API_KEY\"]\n\n"
            "def get(url):\n"
            "    return requests.get(url, headers={\"Authorization\": f\"Bearer {API_KEY}\"})\n"
        ),
        "vuln_lines": [3],
        "explanation": "Hardcoded API key; load from environment or secrets manager.",
    },
    ("CWE-611", "java"): {
        "vulnerable": (
            "import javax.xml.parsers.*;\n"
            "import org.w3c.dom.Document;\n"
            "import java.io.InputStream;\n\n"
            "public class ConfigLoader {\n"
            "    public Document parse(InputStream in) throws Exception {\n"
            "        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
            "        return f.newDocumentBuilder().parse(in);\n"
            "    }\n"
            "}\n"
        ),
        "safe": (
            "import javax.xml.parsers.*;\n"
            "import org.w3c.dom.Document;\n"
            "import java.io.InputStream;\n\n"
            "public class ConfigLoader {\n"
            "    public Document parse(InputStream in) throws Exception {\n"
            "        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
            "        f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
            "        return f.newDocumentBuilder().parse(in);\n"
            "    }\n"
            "}\n"
        ),
        "vuln_lines": [7, 8],
        "explanation": "Default XML parser allows external entities; disable DTD.",
    },
    ("CWE-22", "python"): {
        "vulnerable": (
            "from flask import Flask, request, send_file\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/file\")\n"
            "def get_file():\n"
            "    name = request.args.get(\"name\")\n"
            "    return send_file(f\"/var/uploads/{name}\")\n"
        ),
        "safe": (
            "from pathlib import Path\n"
            "from flask import Flask, request, send_file, abort\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/file\")\n"
            "def get_file():\n"
            "    name = request.args.get(\"name\", \"\")\n"
            "    base = Path(\"/var/uploads\").resolve()\n"
            "    target = (base / name).resolve()\n"
            "    if not target.is_relative_to(base) or not target.is_file():\n"
            "        abort(404)\n"
            "    return send_file(str(target))\n"
        ),
        "vuln_lines": [7],
        "explanation": "User-controlled filename allows path traversal; resolve and bound to base.",
    },
    ("CWE-915", "javascript"): {
        "vulnerable": (
            "function updateUser(target, userInput) {\n"
            "  Object.assign(target, userInput);\n"
            "  return target;\n"
            "}\n"
        ),
        "safe": (
            "const ALLOWED = ['name', 'email'];\n"
            "function updateUser(target, userInput) {\n"
            "  for (const k of ALLOWED) if (k in userInput) target[k] = userInput[k];\n"
            "  return target;\n"
            "}\n"
        ),
        "vuln_lines": [2],
        "explanation": "Object.assign with user input allows prototype pollution; use an allow-list.",
    },
}


def _template_generate(cwe_id: str, language: str) -> Optional[Dict]:
    """Fetch the canned template for (cwe, language), if any."""
    tpl = TEMPLATES.get((cwe_id, language))
    if not tpl:
        return None
    return {
        "vulnerable_code": tpl["vulnerable"],
        "safe_variant": tpl["safe"],
        "explanation": tpl["explanation"],
        "vuln_lines": tpl["vuln_lines"],
    }


def _llm_generate(cwe_id: str, cwe_name: str, language: str) -> Optional[Dict]:
    """Ask the LLM to generate a sample. Returns None on failure."""
    user = (
        f"Generate a code sample for {cwe_id} ({cwe_name}) in {language}. "
        "Return the JSON object described in the system prompt."
    )
    try:
        resp = get_llm().complete(
            system=GENERATOR_SYSTEM_PROMPT, user=user,
            max_tokens=1500, temperature=0.3,
        )
        m = re.search(r"\{.*\}", resp, re.DOTALL)
        if not m:
            return None
        return json.loads(m.group(0))
    except Exception as e:
        logger.warning("LLM generate failed for %s/%s: %s", cwe_id, language, e)
        return None


def generate_samples(count: int, seed: int = 42) -> List[Dict]:
    rng = random.Random(seed)
    samples: List[Dict] = []

    # Expand CWE pool by repeating so we can hit `count`
    pool = TARGET_CWES.copy()
    while len(pool) < count:
        pool.extend(TARGET_CWES)
    rng.shuffle(pool)

    for i, (cwe_id, cwe_name, lang) in enumerate(pool[:count]):
        sample_id = f"SYN-{i+1:03d}"
        if get_llm().mode == "mock":
            gen = _template_generate(cwe_id, lang)
        else:
            gen = _llm_generate(cwe_id, cwe_name, lang) or _template_generate(cwe_id, lang)
        if not gen:
            logger.warning("No template for %s/%s; skipping", cwe_id, lang)
            continue

        # Vulnerable sample
        code = gen["vulnerable_code"]
        # Sniff severity from the CWE category
        severity_map = {
            "CWE-89": "CRITICAL", "CWE-502": "CRITICAL", "CWE-94": "CRITICAL",
            "CWE-78": "HIGH", "CWE-79": "HIGH", "CWE-295": "HIGH",
            "CWE-798": "HIGH", "CWE-611": "HIGH", "CWE-22": "HIGH",
            "CWE-915": "MEDIUM", "CWE-327": "MEDIUM",
        }
        sev = severity_map.get(cwe_id, "MEDIUM")

        vuln_lines = gen.get("vuln_lines") or [1]
        samples.append({
            "sample_id": sample_id,
            "language": lang,
            "code": code,
            "ground_truth": [
                {"cwe_id": cwe_id, "line_start": min(vuln_lines),
                 "line_end": max(vuln_lines), "severity": sev}
            ],
            "explanation": gen.get("explanation", ""),
            "is_synthetic": True,
            "source": "synth.generate",
        })

        # Safe variant
        safe_code = gen["safe_variant"]
        samples.append({
            "sample_id": sample_id + "-SAFE",
            "language": lang,
            "code": safe_code,
            "ground_truth": [],
            "explanation": "Safe variant of " + sample_id,
            "is_synthetic": True,
            "source": "synth.generate",
        })
    return samples


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=15, help="number of vulnerable samples to generate")
    parser.add_argument("--out", default="eval/datasets/synthetic_suite.json")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    samples = generate_samples(args.count, args.seed)
    logger.info("Generated %d samples (vulnerable + safe pairs)", len(samples))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "1.0",
        "description": "Synthetic samples with ground-truth labels. Verified by synth.verify.",
        "samples": samples,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Wrote %s", out_path)


if __name__ == "__main__":
    main()
