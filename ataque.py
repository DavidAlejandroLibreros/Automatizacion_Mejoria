"""Gestión de capturas Wi-Fi de laboratorio y comprobación pasiva de handshake.

No inicia desconexiones de clientes. Las capturas temporales se reemplazan al
iniciar una nueva sesión, únicamente dentro de una carpeta dedicada.
"""

import os
import pty
import re
import select
import shutil
import signal
import subprocess
import time
import threading
from pathlib import Path

CARPETA_CAPTURAS = Path(__file__).resolve().parent / 'capturas_ataque'
EXTENSIONES = ('.cap', '.csv', '.kismet.csv', '.kismet.netxml', '.log.csv', '.airodump.log')
_LECTORES = {}



def _preparar_prefijo(nombre: str) -> Path:
    if not re.fullmatch(r'[A-Za-z0-9_-]+', nombre):
        raise ValueError('El nombre de captura debe ser simple, sin rutas')
    if CARPETA_CAPTURAS.is_symlink():
        raise RuntimeError('La carpeta de capturas no puede ser un enlace simbólico')
    CARPETA_CAPTURAS.mkdir(parents=True, exist_ok=True)
    for archivo in CARPETA_CAPTURAS.iterdir():
        if (archivo.is_file() or archivo.is_symlink()) and archivo.name.startswith(nombre + '-') and archivo.name.endswith(EXTENSIONES):
            archivo.unlink()
    return CARPETA_CAPTURAS / nombre


def _validar_parametros(interfaz: str, bssid: str, canal: str) -> None:
    if not re.fullmatch(r'[A-Za-z0-9_-]+', interfaz):
        raise ValueError('Interfaz inalámbrica inválida')
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', bssid):
        raise ValueError('BSSID inválido')
    if not str(canal).isdigit() or not 1 <= int(canal) <= 165:
        raise ValueError('Canal inválido')


def iniciar_captura_dirigida(interfaz_monitor: str, bssid: str, canal: str, archivo_salida: str = 'captura'):
    """Inicia captura pasiva; retorna (proceso, maestro), como el código original."""
    _validar_parametros(interfaz_monitor, bssid, str(canal))
    if not shutil.which('airodump-ng'):
        raise RuntimeError('No está instalado airodump-ng')
    prefijo = _preparar_prefijo(archivo_salida)
    comando = ['airodump-ng', '--bssid', bssid, '-c', str(canal),
               '--output-format', 'pcap,csv', '--write-interval', '1',
               '-w', str(prefijo), interfaz_monitor]
    maestro, esclavo = pty.openpty()
    try:
        proceso = subprocess.Popen(comando, stdin=subprocess.DEVNULL, stdout=esclavo,
                                   stderr=esclavo, start_new_session=True)
    except Exception:
        os.close(maestro)
        raise
    finally:
        os.close(esclavo)
    # Consumir la salida de la terminal virtual continuamente: de lo contrario,
    # el buffer del PTY puede llenarse y bloquear airodump-ng durante la captura.
    # Guardamos además un registro para diagnosticar por qué no apareció el CAP.
    registro = CARPETA_CAPTURAS / f'{archivo_salida}-airodump.log'
    def vaciar_pty():
        with registro.open('ab') as salida:
            while True:
                try:
                    listo, _, _ = select.select([maestro], [], [], 0.5)
                    if not listo:
                        if proceso.poll() is not None:
                            break
                        continue
                    datos = os.read(maestro, 65536)
                    if not datos:
                        break
                    salida.write(datos)
                    salida.flush()
                except (OSError, ValueError):
                    break
    lector = threading.Thread(target=vaciar_pty, daemon=True)
    _LECTORES[maestro] = lector
    lector.start()
    return proceso, maestro


def ruta_captura(archivo_salida: str = 'captura') -> str:
    """Ruta compatible con el prefijo utilizado por iniciar_captura_dirigida."""
    if not re.fullmatch(r'[A-Za-z0-9_-]+', archivo_salida):
        raise ValueError('Nombre de captura inválido')
    return str(CARPETA_CAPTURAS / f'{archivo_salida}-01.cap')


def detener_captura(proceso: subprocess.Popen, maestro: int) -> None:
    """Cierra la captura de forma ordenada y libera su terminal virtual.

    SIGINT equivale a Ctrl+C; el proceso tiene ocasión de finalizar las
    escrituras del PCAP antes de salir. Solo se fuerza si no responde.
    """
    try:
        if proceso.poll() is None:
            for senal, espera in ((signal.SIGINT, 8), (signal.SIGTERM, 3)):
                try:
                    os.killpg(proceso.pid, senal)
                except ProcessLookupError:
                    break
                try:
                    proceso.wait(timeout=espera)
                    break
                except subprocess.TimeoutExpired:
                    pass
            if proceso.poll() is None:
                try:
                    os.killpg(proceso.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proceso.wait(timeout=3)
    finally:
        lector = _LECTORES.pop(maestro, None)
        if lector is not None:
            lector.join(timeout=2)
        try:
            os.close(maestro)
        except OSError:
            pass


def diagnosticar_pcap(archivo_cap: str) -> dict:
    """Cuenta tramas y EAPOL en un archivo existente usando TShark.

    No infiere que exista un handshake completo a partir de tramas EAPOL.
    Acepta capturas truncadas y devuelve una advertencia para el informe.
    """
    archivo = Path(archivo_cap)
    if not archivo.is_file() or archivo.stat().st_size == 0:
        return {'tramas': 0, 'eapol': 0, 'truncado': False,
                'error': 'No existe un PCAP no vacío'}
    if not shutil.which('tshark'):
        return {'tramas': None, 'eapol': None, 'truncado': False,
                'error': 'TShark no está instalado'}

    def consultar(filtro=None):
        comando = ['tshark', '-n', '-r', str(archivo)]
        if filtro:
            comando += ['-Y', filtro]
        comando += ['-T', 'fields', '-e', 'frame.number']
        return subprocess.run(comando, capture_output=True, text=True, timeout=45)

    try:
        todas = consultar()
        eapol = consultar('eapol')
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'tramas': None, 'eapol': None, 'truncado': False,
                'error': str(exc)}
    errores = '\n'.join((todas.stderr, eapol.stderr))
    truncado = 'cut short' in errores.lower() or 'truncated' in errores.lower()
    if (todas.returncode != 0 or eapol.returncode != 0) and not truncado:
        return {'tramas': None, 'eapol': None, 'truncado': False,
                'error': errores.strip() or 'TShark no pudo leer la captura'}
    return {
        'tramas': len(todas.stdout.splitlines()),
        'eapol': len(eapol.stdout.splitlines()),
        'truncado': truncado,
        'error': None,
    }
