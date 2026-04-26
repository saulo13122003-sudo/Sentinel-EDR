import time
import os
import shutil
import logging
import hashlib
import sqlite3
import stat
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.table import Table
from rich.live import Live
from rich.align import Align

# ---------------- CONFIG ----------------
BASE_DIR = os.getcwd()
FOLDERS = ["Amenazas", "Scripts", "Documentos", "Imagenes", "Otros"]
SAFE_FILES = ["sentinel.py", "sentinel.db", "sentinel_report.log"]

for folder in FOLDERS:
    os.makedirs(folder, exist_ok=True)

logging.basicConfig(
    filename='sentinel_report.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ---------------- DATABASE & AUTO-PATCH ----------------
conn = sqlite3.connect("sentinel.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("PRAGMA journal_mode=WAL;")

# Crear tabla base
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    hash TEXT,
    status TEXT,
    reason TEXT,
    score INTEGER DEFAULT 0,
    date TEXT
)
""")

# PARCHE: Verificar si existe la columna 'score' (evita el error de tu captura)
cursor.execute("PRAGMA table_info(files)")
columns = [column[1] for column in cursor.fetchall()]
if "score" not in columns:
    cursor.execute("ALTER TABLE files ADD COLUMN score INTEGER DEFAULT 0")
    conn.commit()

# ---------------- FUNCIONES NÚCLEO ----------------
def get_file_hash(filepath):
    if not os.path.exists(filepath): return "NO_FILE"
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except: return "HASH_ERROR"

def safe_move(filepath, destination, quarantine=False):
    os.makedirs(destination, exist_ok=True)
    filename = os.path.basename(filepath)
    if quarantine and not filename.endswith(".quarantine"):
        filename += ".quarantine"

    dest_path = os.path.join(destination, filename)
    if os.path.exists(dest_path):
        base, ext = os.path.splitext(filename)
        dest_path = os.path.join(destination, f"{base}_{int(time.time())}{ext}")

    shutil.move(filepath, dest_path)
    if quarantine:
        os.chmod(dest_path, 0o400) # Bloqueo de ejecución
    return dest_path

# ---------------- HANDLER (THE HEALER LOGIC) ----------------
class SentinelHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_action = "Sentinel V4.1 Blindado"
        self.status = "NORMAL"
        self.total_blocked = 0
        self.total_processed = 0

    def on_created(self, event):
        if event.is_directory: return
        filepath = event.src_path
        filename = os.path.basename(filepath)

        if not os.path.exists(filepath): return

        # Ignorar archivos del sistema y de Sentinel
        ignored_ext = ['.db', '.db-journal', '.log', '.tmp']
        if filename in SAFE_FILES or any(filename.endswith(ext) for ext in ignored_ext):
            return

        # Análisis de scoring
        name_parts = filename.split('.')
        extension = f".{name_parts[-1].lower()}" if len(name_parts) > 1 else ""

        score = 0
        reasons = []

        # Reglas de Scoring
        if extension in ['.exe', '.bat', '.cmd', '.vbs', '.scr']:
            score += 3
            reasons.append("EJECUTABLE")
        if len(name_parts) > 2:
            score += 2
            reasons.append("DOBLE_EXT")
        if any(k in filename.lower() for k in ['crack', 'hack', 'exploit', 'patch']):
            score += 2
            reasons.append("KEYWORD")
        if filename.startswith("."):
            score += 1
            reasons.append("OCULTO")

        file_hash = get_file_hash(filepath)
        self.total_processed += 1

        # Lógica de "The Healer" (Detección de recurrencia)
        cursor.execute("SELECT COUNT(*) FROM files WHERE hash=? AND status='BLOCKED'", (file_hash,))
        was_blocked_before = cursor.fetchone()[0]

        try:
            if score >= 3 or was_blocked_before > 0:
                self.status = "ALERTA"
                self.total_blocked += 1
                final_reason = "+".join(reasons) if reasons else "REPETIDO"

                safe_move(filepath, "Amenazas", quarantine=True)

                msg = f"☢️ BLOQUEO: {filename}"
                if was_blocked_before > 0: msg += " (REINCIDENTE)"
                self.last_action = msg

                cursor.execute("INSERT INTO files (name, hash, status, reason, score, date) VALUES (?, ?, ?, ?, ?, ?)",
                             (filename, file_hash, "BLOCKED", final_reason, score, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            else:
                self.status = "NORMAL"
                folder = "Scripts" if extension in ['.py', '.js', '.sh'] else "Documentos" if extension in ['.pdf', '.txt'] else "Imagenes" if extension in ['.png', '.jpg'] else "Otros"
                safe_move(filepath, folder)
                self.last_action = f"✅ OK: {filename} → {folder}"

                cursor.execute("INSERT INTO files (name, hash, status, reason, score, date) VALUES (?, ?, ?, ?, ?, ?)",
                             (filename, file_hash, "OK", "SAFE", score, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

            conn.commit()
        except Exception as e:
            self.last_action = f"❌ Error: {str(e)}"

# ---------------- DASHBOARD ----------------
handler = SentinelHandler()

def generate_dashboard():
    table = Table(title="SENTINEL v4.1 - CORE STATS", expand=True, border_style="magenta")
    table.add_column("Métrica")
    table.add_column("Valor", justify="center")
    table.add_row("Total Procesados", str(handler.total_processed))
    table.add_row("Amenazas (Bóveda)", f"[bold red]{handler.total_blocked}[/bold red]")
    table.add_row("Estatus Núcleo", "[bold green]VIGILANDO[/bold green]" if handler.status == "NORMAL" else "[bold red]¡ATAQUE![/bold red]")

    panel = Panel(
        f"[bold cyan]Log de Acciones:[/bold cyan]\n{handler.last_action}\n\n"
        f"[white]Timestamp:[/white] {datetime.now().strftime('%H:%M:%S')}",
        title="DASHBOARD DE DEFENSA", border_style="red" if handler.status == "ALERTA" else "blue"
    )
    return table, panel

# ---------------- MAIN ----------------
layout = Layout()
layout.split_column(Layout(name="header", size=3), Layout(name="body"))
layout["body"].split_row(Layout(name="stats"), Layout(name="monitor"))

observer = Observer()
observer.schedule(handler, BASE_DIR, recursive=True)
observer.start()

try:
    with Live(layout, refresh_per_second=4, screen=True):
        while True:
            t, p = generate_dashboard()
            layout["header"].update(Panel(Align.center("[bold white]🛡️ THE SENTINEL V4.1 - ADVANCED ENDPOINT PROTECTION[/bold white]"), border_style="white"))
            layout["stats"].update(t)
            layout["monitor"].update(p)
            time.sleep(0.2)
except KeyboardInterrupt:
    observer.stop()
    conn.close()
observer.join()
(sentinel_env) 
