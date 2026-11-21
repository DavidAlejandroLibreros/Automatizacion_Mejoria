"""Escaneo Wi-Fi pasivo con validación de resultados.

Sustituye escaneo.py. Mantiene escanear_redes(interfaz, duracion_segundos,
archivo_salida) y devuelve (redes, estaciones). No transmite tramas.
Los CSV generados son temporales y se eliminan al finalizar.
"""
from __future__ import annotations

import csv
import io
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
CARPETA_TEMPORAL = BASE / "capturas_temporales"
MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _limpiar(nombre: str) -> None:
    if CARPETA_TEMPORAL.is_symlink():
        raise RuntimeError("La carpeta temporal no puede ser un enlace simbólico")
    CARPETA_TEMPORAL.mkdir(parents=True, exist_ok=True)
    # Solo archivos del prefijo exacto de este escáner.
    for archivo in CARPETA_TEMPORAL.glob(f"{nombre}-*"):
        if archivo.is_file() or archivo.is_symlink():
            archivo.unlink()


def _parsear_csv_redes(ruta_csv: str) -> tuple[list[dict], list[dict]]:
    """Acepta las dos tablas del CSV airodump-ng y descarta puntos de acceso incompletos."""
    ruta = Path(ruta_csv)
    if not ruta.is_file():
        raise FileNotFoundError(f"No se generó CSV de escaneo: {ruta}")
    contenido = ruta.read_text(encoding="utf-8-sig", errors="replace")
    redes_por_bssid: dict[str, dict] = {}
    estaciones: list[dict] = []
    seccion = None
    cabeceras = []
    for fila in csv.reader(io.StringIO(contenido)):
        if not fila or not any(c.strip() for c in fila):
            continue
        valores = [c.strip() for c in fila]
        if valores[0] == "BSSID" and "ESSID" in valores:
            seccion, cabeceras = "redes", valores
            continue
        if valores[0] == "Station MAC" and "BSSID" in valores:
            seccion, cabeceras = "estaciones", valores
            continue
        if not seccion:
            continue
        registro = dict(zip(cabeceras, valores))
        if seccion == "redes":
            bssid = registro.get("BSSID", "").upper()
            if not MAC.fullmatch(bssid):
                continue
            canal_raw = registro.get("channel", "")
            try:
                canal = int(canal_raw)
            except ValueError:
                continue
            # Un registro con canal -1 no sirve para captura dirigida.
            if not 1 <= canal <= 14:
                continue
            # Sin identificador de protocolo, el registro suele ser solo tráfico parcial.
            cifrado = registro.get("Privacy", "")
            essid = registro.get("ESSID", "")
            nuevo = {"bssid": bssid, "canal": str(canal),
                     "cifrado": cifrado, "essid": essid}
            antiguo = redes_por_bssid.get(bssid)
            if antiguo is None or (not antiguo["essid"] and essid):
                redes_por_bssid[bssid] = nuevo
        elif seccion == "estaciones":
            mac = registro.get("Station MAC", "").upper()
            bssid = registro.get("BSSID", "").upper()
            if MAC.fullmatch(mac):
                estaciones.append({"mac_cliente": mac,
                                   "bssid_conectado": bssid})
    return list(redes_por_bssid.values()), estaciones


def _capturar_csv(interfaz: str, duracion: float, nombre: str) -> tuple[list[dict], list[dict]]:
    _limpiar(nombre)
    destino = CARPETA_TEMPORAL / nombre
    # El RTL8188EUS se emplea aquí en 2.4 GHz; bg solicita saltar por esa banda.
    comando = ["airodump-ng", "--band", "bg", "--output-format", "csv",
               "--write-interval", "2", "-w", str(destino), interfaz]
    maestro = esclavo = proceso = None
    salida_reciente = bytearray()
    try:
        maestro, esclavo = pty.openpty()
        proceso = subprocess.Popen(comando, stdin=subprocess.DEVNULL,
                                   stdout=esclavo, stderr=esclavo,
                                   start_new_session=True)
        os.close(esclavo)
        esclavo = None
        fin = time.monotonic() + duracion
        while time.monotonic() < fin:
            if proceso.poll() is not None:
                raise RuntimeError(f"airodump-ng terminó antes de tiempo: código {proceso.returncode}")
            disponibles, _, _ = select.select([maestro], [], [], min(.25, max(0, fin-time.monotonic())))
            if disponibles:
                try:
                    fragmento = os.read(maestro, 65536)
                    salida_reciente.extend(fragmento)
                    if len(salida_reciente) > 8192:
                        del salida_reciente[:-8192]
                except OSError:
                    pass
    finally:
        if proceso is not None and proceso.poll() is None:
            try:
                os.killpg(proceso.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
            try:
                proceso.wait(timeout=4)
            except subprocess.TimeoutExpired:
                os.killpg(proceso.pid, signal.SIGTERM)
                try:
                    proceso.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(proceso.pid, signal.SIGKILL)
                    proceso.wait()
        for fd in (esclavo, maestro):
            if fd is not None:
                os.close(fd)
    csv_path = destino.with_name(destino.name + "-01.csv")
    try:
        if not csv_path.is_file():
            return [], []
        return _parsear_csv_redes(str(csv_path))
    finally:
        _limpiar(nombre)


def escanear_redes(interfaz_monitor: str, duracion_segundos: int = 60,
                   archivo_salida: str = "escaneo") -> tuple[list[dict], list[dict]]:
    if not isinstance(duracion_segundos, (int, float)) or not 1 <= duracion_segundos <= 3600:
        raise ValueError("duracion_segundos debe estar entre 1 y 3600")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", interfaz_monitor or ""):
        raise ValueError("Interfaz no válida")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", archivo_salida or ""):
        raise ValueError("Prefijo no válido")
    if not shutil.which("airodump-ng"):
        raise RuntimeError("Falta airodump-ng")
    redes, estaciones = _capturar_csv(interfaz_monitor, duracion_segundos, archivo_salida)
    if not redes:
        print("[AVISO] No se observaron puntos de acceso con canal válido. Reintentando el escaneo...")
        redes, estaciones = _capturar_csv(interfaz_monitor, min(15, duracion_segundos), archivo_salida)
    if not redes:
        raise RuntimeError("Sin redes utilizables. Airodump-ng manual y Python difieren: revisar controlador y proceso de captura.")
    return redes, estaciones
