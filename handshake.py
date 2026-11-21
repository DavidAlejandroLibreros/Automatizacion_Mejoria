"""Confirmación offline de handshakes WPA/WPA2 en capturas de laboratorio.

Solo inspecciona archivos PCAP existentes; no envía tráfico ni prueba claves.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_MAC = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_FILA = re.compile(r"^\s*\d+\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(.+?)\s{2,}(WPA[^\r\n]*)\s*$", re.I)
_HANDSHAKE = re.compile(r"\(\s*(\d+)\s+handshakes?\s*\)", re.I)


def interpretar_listado(salida: str, bssid: str | None = None) -> dict:
    """Interpreta el resumen de redes, sin confundir EAPOL con handshake.

    Si se indica BSSID, la confirmación se limita a ese punto de acceso.
    """
    if bssid is not None and not _MAC.fullmatch(bssid):
        raise ValueError("BSSID inválido")
    redes = []
    for linea in salida.replace('\r', '\n').splitlines():
        coincidencia = _FILA.match(linea)
        if not coincidencia:
            continue
        mac, ssid, cifrado = coincidencia.groups()
        conteo = _HANDSHAKE.search(cifrado)
        redes.append({
            'bssid': mac.upper(),
            'essid': ssid.strip(),
            'handshakes': int(conteo.group(1)) if conteo else 0,
        })

    candidatas = [r for r in redes if bssid is None or r['bssid'] == bssid.upper()]
    total = sum(r['handshakes'] for r in candidatas)
    return {
        'confirmado': total > 0,
        'cantidad': total,
        'redes': candidatas,
        'estado': 'confirmado' if total else ('red_no_encontrada' if bssid and not candidatas else 'sin_confirmacion'),
    }


def confirmar_handshake(archivo_cap: str | Path, bssid: str | None = None, timeout: int = 80) -> dict:
    """Pide a Aircrack-ng que inspeccione un PCAP sin diccionario.

    Aircrack-ng puede terminar con código distinto de cero al no recibir -w;
    eso no implica que la lectura haya fallado. Se interpreta su listado.
    """
    archivo = Path(archivo_cap).expanduser()
    if not archivo.is_file() or archivo.stat().st_size == 0:
        raise FileNotFoundError(f"No existe un PCAP no vacío: {archivo}")
    if bssid is not None and not _MAC.fullmatch(bssid):
        raise ValueError("BSSID inválido")
    ejecutable = shutil.which('aircrack-ng')
    if not ejecutable:
        raise RuntimeError('Aircrack-ng no está instalado')
    try:
        resultado = subprocess.run([ejecutable, str(archivo)], capture_output=True,
                                   text=True, errors='replace', timeout=timeout,
                                   stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Se agotó el tiempo de inspección del PCAP') from exc
    salida = resultado.stdout + '\n' + resultado.stderr
    datos = interpretar_listado(salida, bssid)
    if not datos['redes'] and re.search(r'failed to open|error opening|unknown file type|invalid pcap', salida, re.I):
        raise RuntimeError('Aircrack-ng no pudo leer el PCAP')
    return datos
