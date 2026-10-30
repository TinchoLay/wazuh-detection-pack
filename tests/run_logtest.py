#!/usr/bin/env python3
"""Corre las muestras de honeypot/logtest_*_samples.txt contra wazuh-logtest REAL.

VA EN EL MANAGER DE WAZUH (necesita root para hablar con el motor de reglas):

    cd ~/wazuh-detection-pack
    sudo python3 tests/run_logtest.py              # todo, salvo los casos que piden la lista CDB
    sudo python3 tests/run_logtest.py --cdb        # tambien los de la lista CDB (hace falta registrarla)
    sudo python3 tests/run_logtest.py --verbose    # ademas muestra la salida cruda de logtest

Importante: wazuh-logtest carga las reglas que estan instaladas en el manager
(/var/ossec/etc/rules/), no las de esta carpeta. Primero copiar los archivos al manager, como
dice el README, y despues correr esto.

Cada caso sin "session" corre en un logtest nuevo (estado limpio). Los casos con la misma
"session" comparten un solo logtest, para probar las reglas de frecuencia y de correlacion.

Este programa se escribio sin acceso a un manager: el formato de salida de logtest que lee es el
documentado (bloques "**Phase 1/2/3" con una linea "id: 'NNNNNN'"). Si en tu version el formato
es otro, --verbose muestra la salida cruda y el unico cambio que hace falta esta en parsear_salida().
"""
import argparse
import glob
import os
import re
import subprocess
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import samples  # noqa: E402

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGTEST = "/var/ossec/bin/wazuh-logtest"


def parsear_salida(texto: str) -> List[Optional[int]]:
    """Una entrada por evento: el id de la regla de la fase 3, o None si no disparo ninguna."""
    resultados = []
    for bloque in re.split(r"(?m)^\*\*Phase 1:", texto)[1:]:
        fase3 = re.search(r"\*\*Phase 3:[^\n]*\n(.*?)(?=^\*\*|\Z)", bloque, re.S | re.M)
        if not fase3:
            resultados.append(None)
            continue
        m = re.search(r"^\s*id:\s*'?(\d+)'?", fase3.group(1), re.M)
        resultados.append(int(m.group(1)) if m else None)
    return resultados


def correr_sesion(casos, logtest, verbose=False, timeout=60):
    """Manda los eventos de los casos a un solo proceso de logtest. Devuelve, por caso, la lista
    de ids obtenidos (uno por envio)."""
    lineas = []
    for c in casos:
        lineas += [c.linea] * c.repeat
    proc = subprocess.run(logtest if isinstance(logtest, list) else [logtest],
                          input="\n".join(lineas) + "\n", capture_output=True, text=True, timeout=timeout)
    salida = proc.stdout + proc.stderr
    if verbose:
        print(salida)
    ids = parsear_salida(salida)
    if len(ids) != len(lineas):
        raise RuntimeError(
            f"logtest devolvio {len(ids)} resultados para {len(lineas)} eventos; no se pueden alinear. "
            f"Correr con --verbose y revisar el formato de salida (codigo de salida {proc.returncode}).")
    por_caso, i = [], 0
    for c in casos:
        por_caso.append(ids[i:i + c.repeat])
        i += c.repeat
    return por_caso


def correr(casos, logtest=LOGTEST, con_cdb=False, verbose=False):
    """Devuelve (fallos, salteados, total, lineas_de_reporte)."""
    reporte, fallos, salteados, total = [], 0, 0, 0
    pendientes = []
    for c in casos:
        if c.needs == "cdb" and not con_cdb:
            salteados += 1
            reporte.append(f"SALTEADO {c.donde()} (necesita la lista CDB: usar --cdb)")
        else:
            pendientes.append(c)
    for grupo in samples.agrupar(pendientes):
        try:
            resultados = correr_sesion(grupo, logtest, verbose)
        except RuntimeError as e:
            fallos += len(grupo)
            total += len(grupo)
            reporte.append(f"ERROR   {grupo[0].donde()}: {e}")
            continue
        for c, obtenidos in zip(grupo, resultados):
            if c.setup:
                continue
            total += 1
            ok, detalle = samples.evaluar(c, obtenidos)
            fallos += 0 if ok else 1
            reporte.append(f"{'OK     ' if ok else 'FALLO  '} {c.donde()} {detalle}")
    return fallos, salteados, total, reporte


def main(argv=None):
    ap = argparse.ArgumentParser(description="Muestras de reglas contra wazuh-logtest real (en el manager)")
    ap.add_argument("archivos", nargs="*", help="archivos de muestras (por defecto honeypot/logtest_*_samples.txt)")
    ap.add_argument("--cdb", action="store_true", help="incluir los casos que necesitan la lista CDB")
    ap.add_argument("--verbose", action="store_true", help="mostrar la salida cruda de logtest")
    ap.add_argument("--logtest", default=LOGTEST, help=f"ruta de wazuh-logtest ({LOGTEST})")
    a = ap.parse_args(argv)

    archivos = a.archivos or sorted(glob.glob(os.path.join(RAIZ, "honeypot", "logtest_*_samples.txt")))
    casos = []
    for ruta in archivos:
        casos += samples.parsear(open(ruta, encoding="utf-8").read(), os.path.relpath(ruta, RAIZ))
    fallos, salteados, total, reporte = correr(casos, a.logtest, a.cdb, a.verbose)
    print("\n".join(reporte))
    print(f"\n{total - fallos}/{total} casos bien, {fallos} con fallos, {salteados} salteados.")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
