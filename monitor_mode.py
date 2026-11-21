"""Activación de modo monitor con cierre de procesos interferentes.

Cierra los procesos que impiden el modo monitor (NetworkManager, wpa_supplicant,
dhclient, etc.) y activa el modo monitor en la interfaz indicada. Pensado para
Kali Linux con la suite aircrack-ng. Requiere privilegios de root.
"""
import subprocess
import time
import re

def listar_interfaces_wifi() -> list[dict]:
    """Lista las interfaces inalámbricas y su tipo usando 'iw dev'.

    Devuelve, p. ej.: [{'nombre': 'wlan0', 'tipo': 'managed'}].
    """
    resultado = subprocess.run(["iw", "dev"], capture_output=True, text=True,
                               check=False, timeout=10)
    interfaces = []
    for linea in resultado.stdout.splitlines():
        texto = linea.strip()
        coincidencia = re.match(r"Interface\s+(\S+)", texto)
        if coincidencia:
            interfaces.append({"nombre": coincidencia.group(1), "tipo": "desconocido"})
        elif texto.startswith("type ") and interfaces:
            interfaces[-1]["tipo"] = texto.split(None, 1)[1]
    return interfaces


def matar_procesos_interferentes() -> None:
    """Ejecuta 'airmon-ng check kill' (paso 3 del procedimiento WPA).

    Cierra los procesos que rompen el modo monitor y provocan el error
    'No such BSSID available' al mover el canal. Es best-effort: si algo
    falla, avisa pero no detiene el programa.
    """
    print("[INFO] Cerrando procesos que interfieren con el modo monitor...")
    try:
        resultado = subprocess.run(
            ["airmon-ng", "check", "kill"],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[AVISO] No se pudo ejecutar 'airmon-ng check kill': {exc}")
        return
    if resultado.returncode == 0:
        print("[OK] Procesos interferentes cerrados (NetworkManager, wpa_supplicant, etc.).")
    else:
        print("[AVISO] 'airmon-ng check kill' terminó con avisos; se continúa.")


def verificar_modo_monitor(interfaz: str) -> bool:
    """Comprueba si una interfaz está en modo monitor."""
    resultado = subprocess.run(
        ["iw", "dev", interfaz, "info"],
        capture_output=True, text=True, check=False, timeout=10,
    )
    if resultado.returncode != 0:
        raise RuntimeError(
            f"No se pudo consultar {interfaz}: {resultado.stderr.strip()}"
        )
    return any(
        linea.strip() == "type monitor"
        for linea in resultado.stdout.splitlines()
    )


def iniciar_modo_monitor(interfaz: str) -> str:
    """Cierra procesos interferentes, activa el modo monitor y devuelve el
    nombre final de la interfaz configurada.
    """
    print(f"Verificando interfaz {interfaz}...")

    # Paso clave y nuevo: cerrar los procesos que estorban ANTES de todo.
    # Sin esto, NetworkManager/wpa_supplicant mueven el canal y aireplay-ng
    # falla con 'No such BSSID available'.
    matar_procesos_interferentes()

    # Si ya está en modo monitor, no se vuelve a configurar.
    if verificar_modo_monitor(interfaz):
        print(f"[OK] {interfaz} ya está en modo monitor.")
        return interfaz

    print(f"[INFO] {interfaz} no está en modo monitor.")
    print("[INFO] Intentando activarlo automáticamente...")

    resultado = subprocess.run(
        ["airmon-ng", "start", interfaz],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if resultado.returncode != 0:
        raise RuntimeError(
            "No se pudo activar el modo monitor:\n"
            + resultado.stdout + resultado.stderr
        )

    # Dar tiempo al controlador para actualizar la interfaz.
    time.sleep(2)

    # Algunos controladores conservan el nombre (wlan0) y otros lo cambian
    # (wlan0mon). El RTL8188EUS suele conservarlo.
    for candidato in (interfaz, f"{interfaz}mon"):
        try:
            if verificar_modo_monitor(candidato):
                print(f"[OK] Modo monitor activado en {candidato}.")
                return candidato
        except RuntimeError:
            continue

    raise RuntimeError(
        "Airmon-ng terminó, pero no se encontró una interfaz en modo monitor."
    )