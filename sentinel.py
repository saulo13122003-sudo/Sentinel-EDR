"""
SENTINEL EDR PRO - ShadowWatch AI (v2)
----------------------------------------------------
Monitor de red en tiempo real con auditoría forense, whitelist,
decaimiento de amenazas, exportación de reportes y bloqueo real
opcional vía iptables (requiere permisos y confirmación explícita).

Requisitos:
    pip install psutil textual

Ejecutar con más visibilidad de conexiones de otros procesos:
    sudo python3 sentinel_edr_pro.py

----------------------------------------------------
Copyright (c) 2026 Carlos [Feliz Baez]
Todos los derechos reservados.

Este software se distribuye "tal cual", sin garantía de ningún tipo,
expresa o implícita. El autor no se hace responsable de daños derivados
del uso, mal uso, o de las acciones de bloqueo real de red (iptables)
ejecutadas mediante esta herramienta. Uso bajo tu propio riesgo y
únicamente en sistemas/redes que administres o estés autorizado a auditar.

Queda prohibida la redistribución o modificación de este código sin
autorización expresa del autor.
----------------------------------------------------
"""

import csv
import json
import os
import shutil
import subprocess
import time
from datetime import datetime
from collections import defaultdict

import psutil
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Button, DataTable, ProgressBar, Log, Input
from textual.reactive import reactive

# ----------------------------------------------------------------------------
# CONFIGURACIÓN
# ----------------------------------------------------------------------------

__copyright__ = "Copyright (c) 2026 Carlos [UNICARIBE]. Todos los derechos reservados."
__license__ = "Uso restringido. No redistribuir ni modificar sin autorización del autor."

COPYRIGHT_BANNER = f"""
╔══════════════════════════════════════════════════════════════════╗
║  SENTINEL EDR PRO - ShadowWatch AI v2                               ║
║  {__copyright__:<68}║
║  {__license__:<68}║
║  Uso bajo tu propio riesgo. Solo en sistemas que administres.       ║
╚══════════════════════════════════════════════════════════════════╝
"""

CONFIG = {
    # Puertos que se consideran de riesgo si aparecen en conexiones entrantes/salientes
    "PUERTOS_CRITICOS": {4444, 5555, 8080, 1337, 31337, 6666, 6667},
    "PUERTOS_SENSIBLES": {22, 3389, 23, 445, 135, 139},  # requieren vigilancia, no siempre maliciosos
    # IPs/hosts que nunca se deben marcar como amenaza (tu propia infraestructura, DNS, etc.)
    "WHITELIST": {"127.0.0.1", "::1", "0.0.0.0"},
    # Segundos tras los cuales una amenaza sin nueva actividad baja de score (decaimiento)
    "DECAY_INTERVAL_SEG": 30,
    "DECAY_AMOUNT": 5,
    # Segundos tras los cuales una entrada limpia (score 0, status Safe/Clean) se elimina de la tabla
    "TTL_LIMPIEZA_SEG": 300,
    "EXPORT_DIR": os.path.expanduser("~/sentinel_reports"),
    "LOG_FILE": os.path.expanduser("~/sentinel_edr.log"),
    "SCAN_INTERVAL_SEG": 2.0,
}

THREAT_INTEL = {
    "172.16.0.7": {
        "score": 95,
        "analysis": "🔥 CRITICAL METASPLOIT",
        "status": "Malicious",
        "vector": "Remote Code Execution (RCE) / Reverse Shell (Payload: linux/x64/meterpreter/reverse_tcp)",
        "puerto_afectado": "4444",
        "mitigacion": "Bloquear tráfico entrante/saliente mediante iptables y matar PID del proceso padre.",
    },
    "10.0.0.15": {
        "score": 48,
        "analysis": "⚡ SUSPICIOUS BEACONING",
        "status": "Warning",
        "vector": "Anomalía de Red / C2 Beaconing detectado con intervalos repetitivos (Posible Cobalt Strike)",
        "puerto_afectado": "8080",
        "mitigacion": "Aislar host de la VLAN, volcar memoria RAM para análisis de strings y renovar llaves SSH.",
    },
}

THREAT_DB = defaultdict(
    lambda: {
        "score": 0,
        "analysis": "Stable",
        "status": "Safe",
        "last_seen": "-",
        "last_seen_ts": 0.0,
        "proceso": "-",
        "pid": "-",
        "puerto": "-",
        "blocked": False,
    }
)


class SentinelProApp(App):
    """EDR Cyberpunk Avanzado e Interactivo - ShadowWatch AI v2"""

    CSS = """
    Screen {
        background: #0a0512;
    }
    #app-header {
        background: #160d29;
        color: #00ffcc;
        text-style: bold;
    }
    #main-layout {
        layout: grid;
        grid-size: 2;
        grid-columns: 2fr 1fr;
        padding: 1;
    }
    .panel-box {
        border: round #321054;
        background: #11091c;
        margin: 1;
        padding: 1;
    }
    #threat-panel {
        border-title-color: #00ffcc;
        border-title-style: bold;
    }
    #log-panel {
        border-title-color: #ff007f;
        border-title-style: bold;
    }
    #control-bar {
        height: 6;
        margin: 1;
        padding: 1;
        background: #160d29;
        border: solid #3b2463;
    }
    #stats-bar {
        height: 3;
        margin: 0 1 1 1;
        padding: 0 1;
        background: #160d29;
        border: solid #3b2463;
        color: #00ffcc;
    }
    #search-box {
        margin: 0 1 1 1;
    }
    Button {
        margin-right: 2;
        text-style: bold;
    }
    #btn-start {
        background: #004433;
        color: #00ff88;
        border: tall #00ffaa;
    }
    #btn-start:hover {
        background: #00aa77;
        color: #ffffff;
    }
    #btn-stop {
        background: #440011;
        color: #ff0055;
        border: tall #ff0055;
    }
    #btn-stop:hover {
        background: #aa0033;
        color: #ffffff;
    }
    #btn-export {
        background: #1a1033;
        color: #ffd700;
        border: tall #ffd700;
    }
    #btn-export:hover {
        background: #4a3a00;
        color: #ffffff;
    }
    ProgressBar {
        width: 100%;
        margin-top: 1;
    }
    .bar--bar {
        background: #221133;
    }
    .bar--complete {
        background: #00ffcc;
    }
    """

    BINDINGS = [
        ("s", "toggle_scan", "Iniciar/Detener Escaneo"),
        ("x", "execute_counterattack", "Neutralizar (Purga lógica)"),
        ("b", "block_real", "Bloquear con iptables (real)"),
        ("e", "export_report", "Exportar Reporte"),
        ("f", "focus_search", "Buscar/Filtrar"),
        ("q", "quit", "Apagar EDR"),
    ]

    scanning_active = reactive(False)
    system_status_text = reactive("ESTADO: [bold yellow]STANDBY[/bold yellow] - Esperando Operador")
    filtro_actual = reactive("")

    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.decay_worker = None
        self.total_conexiones_vistas = 0
        self.total_amenazas_detectadas = 0
        self.hora_inicio = datetime.now()
        self.row_key_to_ip = {}

        for ip, info in THREAT_INTEL.items():
            THREAT_DB[ip] = {
                "score": info["score"],
                "analysis": info["analysis"],
                "status": info["status"],
                "last_seen": datetime.now().strftime("%H:%M:%S"),
                "last_seen_ts": time.time(),
                "proceso": "-",
                "pid": "-",
                "puerto": info.get("puerto_afectado", "-"),
                "blocked": False,
            }

    # ------------------------------------------------------------------
    # COMPOSICIÓN DE LA UI
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True, id="app-header")

        with Horizontal(id="control-bar"):
            with Vertical():
                yield Static(self.system_status_text, id="status-display")
                yield ProgressBar(total=100, show_eta=False, id="scan-bar")
            yield Button("⚡ INICIAR MOTOR", id="btn-start", variant="success")
            yield Button("🛑 ABORTAR", id="btn-stop", variant="error")
            yield Button("💾 EXPORTAR", id="btn-export")

        yield Static("", id="stats-bar")
        yield Input(placeholder="Filtrar por IP, estado o análisis... (tecla F)", id="search-box")

        with Container(id="main-layout"):
            with Vertical(id="threat-panel", classes="panel-box"):
                yield Static(
                    "[bold #00ffcc]🕵️ MOTOR DE AMENAZAS (Clic o Flechas + Enter | X: neutralizar | B: bloquear real)[/bold #00ffcc]\n"
                )
                yield DataTable(id="threat-table")

            with Vertical(id="log-panel", classes="panel-box"):
                yield Static("[bold #ff007f]📜 INTELIGENCIA FORENSE Y LIVE LOGS[/bold #ff007f]\n")
                yield Log(id="live-logs")

        yield Footer()

    # ------------------------------------------------------------------
    # CICLO DE VIDA
    # ------------------------------------------------------------------
    def on_mount(self) -> None:
        self.title = "SENTINEL EDR PRO [SHADOWWATCH AI v2]"
        self.sub_title = "Auditoría de Red en Tiempo Real © 2026 Carlos [UNICARIBE]"

        table = self.query_one("#threat-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("ORIGEN / IP", "ANÁLISIS DE AMENAZA", "ESTADO", "PROCESO", "PUERTO", "ÚLTIMA VISTA")

        os.makedirs(CONFIG["EXPORT_DIR"], exist_ok=True)

        self.log_message("ShadowWatch AI v2: Kernel inicializado con éxito.")
        self.log_message(f"Whitelist activa: {sorted(CONFIG['WHITELIST'])}")
        if os.geteuid() != 0:
            self.log_message("[WARN] No corres como root: visibilidad de procesos ajenos limitada (psutil).")
        if shutil.which("iptables") is None:
            self.log_message("[WARN] 'iptables' no encontrado en PATH: el bloqueo real (tecla B) no funcionará.")

        self.refresh_threat_table()
        self.update_stats_bar()
        self.set_interval(1.0, self.update_system_stats)
        self.set_interval(5.0, self.decay_and_cleanup)

    def watch_scanning_active(self, active: bool) -> None:
        p_bar = self.query_one("#scan-bar", ProgressBar)
        if active:
            self.system_status_text = "ESTADO: [bold #00ff88]DEFENSA ACTIVA[/bold #00ff88] - Analizando Tráfico de Red"
            p_bar.progress = 100
            self.log_message("[OK] Motor de búsqueda en tiempo real levantado.")
            self.scan_worker = self.run_worker(self.real_network_scanner, thread=True)
        else:
            self.system_status_text = "ESTADO: [bold yellow]STANDBY[/bold yellow] - Sistema en Espera"
            p_bar.progress = 0
            self.log_message("[WARN] Monitoreo en background pausado.")
            if self.scan_worker:
                self.scan_worker.cancel()
                self.scan_worker = None

        self.query_one("#status-display", Static).update(self.system_status_text)

    def watch_filtro_actual(self, _valor: str) -> None:
        self.refresh_threat_table()

    # ------------------------------------------------------------------
    # ACCIONES DE UI
    # ------------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.scanning_active = True
        elif event.button.id == "btn-stop":
            self.scanning_active = False
        elif event.button.id == "btn-export":
            self.action_export_report()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-box":
            self.filtro_actual = event.value.strip().lower()

    def action_toggle_scan(self) -> None:
        self.scanning_active = not self.scanning_active

    def action_focus_search(self) -> None:
        self.query_one("#search-box", Input).focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        ip = self.row_key_to_ip.get(event.row_key)
        if ip:
            self.display_forensics(ip)

    def _ip_seleccionada_actual(self):
        table = self.query_one("#threat-table", DataTable)
        if table.cursor_row is None or table.row_count == 0:
            return None
        try:
            row_keys = list(table.rows.keys())
            target_key = row_keys[table.cursor_row]
            return self.row_key_to_ip.get(target_key)
        except (IndexError, KeyError):
            return None

    def display_forensics(self, ip_seleccionada: str) -> None:
        self.log_message(f"--- 🔍 EXAMEN FORENSE EN DETALLE: {ip_seleccionada} ---")
        if ip_seleccionada in THREAT_INTEL:
            intel = THREAT_INTEL[ip_seleccionada]
            self.log_message(f"[ALERTA] Vector: {intel['vector']}")
            self.log_message(f"[PUERTO] Target Port detectado: {intel['puerto_afectado']}")
            self.log_message(f"[REMEDIO] Acción recomendada: {intel['mitigacion']}")
            self.log_message("[TIP] X = neutralizar (lógico) | B = bloquear con iptables (real)")
        else:
            datos = THREAT_DB.get(ip_seleccionada)
            if datos:
                self.log_message(f"[PROCESO] {datos.get('proceso', '-')} (PID {datos.get('pid', '-')})")
                self.log_message(f"[PUERTO] {datos.get('puerto', '-')} | Score: {datos.get('score', 0)}")
            self.log_message("[INFO] Dirección IP sin inteligencia previa registrada.")
        self.log_message("---------------------------------------------------------")

    # ------------------------------------------------------------------
    # NEUTRALIZACIÓN LÓGICA (no toca el sistema)
    # ------------------------------------------------------------------
    def action_execute_counterattack(self) -> None:
        ip_target = self._ip_seleccionada_actual()
        if not ip_target:
            self.log_message("[!] Error: selecciona una fila válida en la tabla primero.")
            return

        self.log_message(f"[🔥 NEUTRALIZACIÓN] Marcando {ip_target} como resuelto (lógico, no de red)...")
        self.log_message("[KILLED] Estado de amenaza reseteado en base de datos local.")

        if ip_target in THREAT_DB:
            THREAT_DB[ip_target]["analysis"] = "🛡️ NEUTRALIZED BY OPERATOR"
            THREAT_DB[ip_target]["status"] = "Clean"
            THREAT_DB[ip_target]["score"] = 0
            THREAT_DB[ip_target]["last_seen_ts"] = time.time()

        self.refresh_threat_table()
        self.log_message(f"[SUCCESS] {ip_target} marcado como neutralizado.")

    # ------------------------------------------------------------------
    # BLOQUEO REAL VÍA IPTABLES (acción con efecto real en el sistema)
    # ------------------------------------------------------------------
    def action_block_real(self) -> None:
        ip_target = self._ip_seleccionada_actual()
        if not ip_target:
            self.log_message("[!] Error: selecciona una fila válida en la tabla primero.")
            return
        if ip_target in CONFIG["WHITELIST"]:
            self.log_message(f"[!] {ip_target} está en whitelist, no se bloquea.")
            return
        if shutil.which("iptables") is None:
            self.log_message("[!] 'iptables' no está disponible en este sistema/PATH.")
            return

        datos = THREAT_DB.get(ip_target)
        if datos and datos.get("blocked"):
            self.log_message(f"[INFO] {ip_target} ya tiene una regla de bloqueo activa.")
            return

        self.log_message(f"[FW] Ejecutando: iptables -A INPUT -s {ip_target} -j DROP")
        try:
            resultado = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_target, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if resultado.returncode == 0:
                self.log_message(f"[SUCCESS] Regla de firewall aplicada contra {ip_target}.")
                if ip_target in THREAT_DB:
                    THREAT_DB[ip_target]["blocked"] = True
                    THREAT_DB[ip_target]["status"] = "Blocked"
                    THREAT_DB[ip_target]["analysis"] = "🚫 BLOQUEADO EN FIREWALL (iptables)"
                self.refresh_threat_table()
            else:
                self.log_message(f"[ERROR] iptables falló: {resultado.stderr.strip()}")
                self.log_message("[TIP] ¿Corriste el programa con sudo/permisos de root?")
        except FileNotFoundError:
            self.log_message("[ERROR] iptables no encontrado.")
        except subprocess.TimeoutExpired:
            self.log_message("[ERROR] Comando iptables expiró (timeout).")
        except Exception as exc:
            self.log_message(f"[ERROR] Fallo inesperado al bloquear: {exc}")

    # ------------------------------------------------------------------
    # EXPORTACIÓN DE REPORTES
    # ------------------------------------------------------------------
    def action_export_report(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(CONFIG["EXPORT_DIR"], f"sentinel_report_{timestamp}")
        csv_path = base + ".csv"
        json_path = base + ".json"

        rows = []
        for ip, datos in THREAT_DB.items():
            rows.append(
                {
                    "ip": ip,
                    "score": datos["score"],
                    "analysis": datos["analysis"],
                    "status": datos["status"],
                    "proceso": datos.get("proceso", "-"),
                    "pid": datos.get("pid", "-"),
                    "puerto": datos.get("puerto", "-"),
                    "last_seen": datos["last_seen"],
                    "blocked": datos.get("blocked", False),
                }
            )

        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else
                                         ["ip", "score", "analysis", "status", "proceso", "pid", "puerto", "last_seen", "blocked"])
                writer.writeheader()
                writer.writerows(rows)

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(rows, f, ensure_ascii=False, indent=2)

            self.log_message(f"[EXPORT] Reporte guardado: {csv_path}")
            self.log_message(f"[EXPORT] Reporte guardado: {json_path}")
        except Exception as exc:
            self.log_message(f"[ERROR] No se pudo exportar el reporte: {exc}")

    # ------------------------------------------------------------------
    # DECAIMIENTO Y LIMPIEZA AUTOMÁTICA
    # ------------------------------------------------------------------
    def decay_and_cleanup(self) -> None:
        ahora = time.time()
        a_eliminar = []

        for ip, datos in list(THREAT_DB.items()):
            if ip in THREAT_INTEL:
                continue  # las amenazas base de inteligencia no decaen ni se eliminan

            inactivo_seg = ahora - datos.get("last_seen_ts", ahora)

            if datos["score"] > 0 and inactivo_seg > CONFIG["DECAY_INTERVAL_SEG"]:
                nuevo_score = max(0, datos["score"] - CONFIG["DECAY_AMOUNT"])
                datos["score"] = nuevo_score
                if nuevo_score == 0 and datos["status"] != "Blocked":
                    datos["status"] = "Safe"
                    datos["analysis"] = "Stable (decayed)"

            es_limpia = datos["score"] == 0 and datos["status"] in ("Safe", "Clean")
            if es_limpia and inactivo_seg > CONFIG["TTL_LIMPIEZA_SEG"]:
                a_eliminar.append(ip)

        for ip in a_eliminar:
            del THREAT_DB[ip]

        if a_eliminar:
            self.refresh_threat_table()

    # ------------------------------------------------------------------
    # ESTADÍSTICAS Y ESTADO DEL SISTEMA
    # ------------------------------------------------------------------
    def update_system_stats(self) -> None:
        try:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.sub_title = f"CPU: {cpu}% | RAM: {ram}% | Auditoría en tiempo real"
        except Exception:
            pass
        self.update_stats_bar()

    def update_stats_bar(self) -> None:
        activas = sum(1 for d in THREAT_DB.values() if d["status"] in ("Malicious", "Warning"))
        bloqueadas = sum(1 for d in THREAT_DB.values() if d.get("blocked"))
        uptime = datetime.now() - self.hora_inicio
        uptime_str = str(uptime).split(".")[0]

        texto = (
            f"📡 Conexiones vistas: {self.total_conexiones_vistas} | "
            f"⚠️ Amenazas detectadas (histórico): {self.total_amenazas_detectadas} | "
            f"🔴 Activas ahora: {activas} | 🚫 Bloqueadas: {bloqueadas} | ⏱️ Uptime: {uptime_str}"
        )
        try:
            self.query_one("#stats-bar", Static).update(texto)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # ESCÁNER DE RED EN SEGUNDO PLANO
    # ------------------------------------------------------------------
    def real_network_scanner(self) -> None:
        while self.scanning_active:
            try:
                connections = psutil.net_connections(kind="inet")
            except psutil.AccessDenied:
                self.call_from_thread(
                    self.log_message,
                    "[ERROR] Permiso denegado leyendo conexiones. Ejecuta con sudo para ver todos los procesos.",
                )
                time.sleep(CONFIG["SCAN_INTERVAL_SEG"])
                continue
            except Exception as exc:
                self.call_from_thread(self.log_message, f"[ERROR] Fallo leyendo conexiones: {exc}")
                time.sleep(CONFIG["SCAN_INTERVAL_SEG"])
                continue

            for conn in connections:
                if not self.scanning_active:
                    return
                if not conn.raddr:
                    continue

                ip_remota = conn.raddr.ip
                puerto = conn.raddr.port

                if ip_remota in CONFIG["WHITELIST"]:
                    continue

                self.total_conexiones_vistas += 1
                now = datetime.now().strftime("%H:%M:%S")
                nombre_proceso = "-"
                if conn.pid:
                    try:
                        nombre_proceso = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        nombre_proceso = "desconocido"

                es_critico = puerto in CONFIG["PUERTOS_CRITICOS"]
                es_sensible = puerto in CONFIG["PUERTOS_SENSIBLES"]

                if ip_remota not in THREAT_DB or THREAT_DB[ip_remota]["status"] == "Safe":
                    if es_critico:
                        THREAT_DB[ip_remota] = {
                            "score": 85,
                            "analysis": f"⚠️ ALERTA: Puerto Crítico {puerto} Detectado",
                            "status": "Warning",
                            "last_seen": now,
                            "last_seen_ts": time.time(),
                            "proceso": nombre_proceso,
                            "pid": conn.pid or "-",
                            "puerto": puerto,
                            "blocked": False,
                        }
                        self.total_amenazas_detectadas += 1
                        self.call_from_thread(
                            self.log_message,
                            f"[RED] Conexión sospechosa: {ip_remota}:{puerto} ({nombre_proceso}, PID {conn.pid})",
                        )
                        self.call_from_thread(self.refresh_threat_table)
                    elif es_sensible:
                        THREAT_DB[ip_remota] = {
                            "score": 30,
                            "analysis": f"👁️ Vigilancia: puerto sensible {puerto}",
                            "status": "Warning",
                            "last_seen": now,
                            "last_seen_ts": time.time(),
                            "proceso": nombre_proceso,
                            "pid": conn.pid or "-",
                            "puerto": puerto,
                            "blocked": False,
                        }
                        self.call_from_thread(self.refresh_threat_table)
                else:
                    THREAT_DB[ip_remota]["last_seen"] = now
                    THREAT_DB[ip_remota]["last_seen_ts"] = time.time()
                    THREAT_DB[ip_remota]["proceso"] = nombre_proceso
                    THREAT_DB[ip_remota]["puerto"] = puerto

            time.sleep(CONFIG["SCAN_INTERVAL_SEG"])

    # ------------------------------------------------------------------
    # LOGGING
    # ------------------------------------------------------------------
    def log_message(self, text: str) -> None:
        linea = f"[{datetime.now().strftime('%H:%M:%S')}] {text}"
        self.query_one("#live-logs", Log).write_line(linea)
        try:
            with open(CONFIG["LOG_FILE"], "a", encoding="utf-8") as f:
                f.write(linea + "\n")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # RENDERIZADO DE TABLA (con filtro y orden por score)
    # ------------------------------------------------------------------
    def refresh_threat_table(self) -> None:
        table = self.query_one("#threat-table", DataTable)
        current_row = table.cursor_row
        table.clear()
        self.row_key_to_ip.clear()

        filtro = self.filtro_actual

        items = sorted(THREAT_DB.items(), key=lambda kv: kv[1]["score"], reverse=True)

        for ip, datos in items:
            if filtro:
                haystack = f"{ip} {datos['status']} {datos['analysis']}".lower()
                if filtro not in haystack:
                    continue

            score = datos["score"]
            if datos["status"] == "Malicious":
                status_tag = f"[red]{datos['status']}[/red]"
            elif datos["status"] == "Warning":
                status_tag = f"[yellow]{datos['status']}[/yellow]"
            elif datos["status"] == "Blocked":
                status_tag = f"[magenta]{datos['status']}[/magenta]"
            else:
                status_tag = f"[green]{datos['status']}[/green]"

            row_key = table.add_row(
                ip,
                f"[{score}] {datos['analysis']}",
                status_tag,
                datos.get("proceso", "-"),
                str(datos.get("puerto", "-")),
                datos["last_seen"],
            )
            self.row_key_to_ip[row_key] = ip

        self.update_stats_bar()

        if current_row is not None and current_row < table.row_count:
            try:
                table.move_cursor(row=current_row)
            except Exception:
                pass


if __name__ == "__main__":
    print(COPYRIGHT_BANNER)
    app = SentinelProApp()
    app.run()
