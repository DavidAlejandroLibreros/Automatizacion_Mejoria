from __future__ import annotations

import re
import subprocess
from pathlib import Path

_MAC = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _limpiar_salida(texto: str) -> str:
    # Algunas versiones presentan progreso en líneas sobrescritas con \r.
    return _ANSI.sub("", texto).replace("\r", "\n")


def _extraer_contrasena(salida: str) -> str | None:
    """Extrae un resultado reconocido, sin imprimirlo ni registrarlo."""
    match = re.search(r"KEY\s+FOUND!\s*\[\s*(.*?)\s*\]", salida, re.I)
    return match.group(1) if match else None


def _extraer_paquetes_leidos(salida: str) -> int | None:
    encontrados = re.findall(r"\bRead\s+([\d,]+)\s+packets?\b", salida, re.I)
    return int(encontrados[-1].replace(",", "")) if encontrados else None


def _extraer_claves_probadas(salida: str) -> int | None:
    """Devuelve el número reportado; None si el programa no lo informa."""
    # Admitir versiones que muestren '123/456 keys tested'.
    encontrados = re.findall(r"\b([\d,]+)\s*/\s*[\d,]+\s+keys?\s+tested\b", salida, re.I)
    if encontrados:
        return int(encontrados[-1].replace(",", ""))
    # Algunas salidas utilizan '123 keys tested'.
    encontrados = re.findall(r"\b([\d,]+)\s+keys?\s+tested\b", salida, re.I)
    return int(encontrados[-1].replace(",", "")) if encontrados else None


def interpretar_salida(salida: str) -> dict:
    """Analiza texto de muestra sin ejecutar herramientas ni usar la red."""
    texto = _limpiar_salida(salida)
    contrasena = _extraer_contrasena(texto)
    return {
        "encontrada": contrasena is not None,
        "contrasena": contrasena,
        "paquetes_leidos": _extraer_paquetes_leidos(texto),
        "claves_probadas": _extraer_claves_probadas(texto),
        "salida_completa": texto,
    }


def crackear(archivo_cap: str, bssid: str, diccionario: str) -> dict:
    """Ejecuta el análisis de una captura y devuelve resultados compatibles con main.py.
    """
    captura = Path(archivo_cap).expanduser().resolve()
    lista = Path(diccionario).expanduser().resolve()
    if not captura.is_file() or captura.stat().st_size == 0:
        raise ValueError("El archivo de captura no existe o está vacío.")
    if not lista.is_file() or lista.stat().st_size == 0:
        raise ValueError("El diccionario no existe o está vacío.")
    if not _MAC.fullmatch(bssid):
        raise ValueError("El BSSID debe tener el formato AA:BB:CC:DD:EE:FF.")

    try:
        resultado = subprocess.run(
            ["aircrack-ng", str(captura), "-w", str(lista), "-b", bssid],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=300,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("No se encontró aircrack-ng en el sistema.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("El análisis excedió el límite de 300 segundos.") from exc

    salida = (resultado.stdout or "") + "\n" + (resultado.stderr or "")
    analisis = interpretar_salida(salida)
    # Una salida sin éxito no debe interpretarse como una contraseña incorrecta
    # si la herramienta terminó por un error de entrada o ejecución.
    if (resultado.returncode != 0 and not analisis["encontrada"]
            and not re.search(r"KEY NOT FOUND|Passphrase not in dictionary", salida, re.I)):
        # Evitar volcar stdout/stderr: pueden contener información sensible.
        raise RuntimeError(
            f"aircrack-ng terminó con código {resultado.returncode}. "
            "Revisa el formato de captura, el diccionario y la salida local."
        )
    return analisis
