#!/usr/bin/env python3
"""Chequeos estaticos de las reglas de Wazuh de este repo. Solo libreria estandar.

    python tests/check_rules.py            # sale con 1 si hay errores

Que comprueba (y por que):
- Cada archivo es XML estricto. Wazuh es mas permisivo que el XML estandar (acepta "--" dentro de
  un comentario, por ejemplo), pero un archivo que otras herramientas no pueden leer es una trampa.
- IDs unicos entre todos los archivos y dentro del rango de reglas propias (100000 a 119999).
- Cada regla tiene nivel entre 0 y 15 y descripcion.
- Los padres existen (en el repo o en la lista de reglas de fabrica) y se cargan ANTES que sus hijas.
  Wazuh carga los archivos en orden alfabetico: una hija que carga antes que su padre da errores.
- Las reglas de frecuencia tienen frequency, timeframe y un if_matched_*.
- Las etiquetas MITRE tienen formato valido.
- Cada ID esta mencionado en el README que corresponde (documentacion al dia).
- Los IDs que usan las muestras de logtest existen, y cada regla del honeypot tiene al menos una
  muestra que la espera (cobertura).
- Ninguna IP publica de terceros en el repo: solo rangos de documentacion (RFC 5737), privadas,
  loopback y unos pocos DNS publicos usados como ejemplo.

Lo que NO comprueba: que las reglas detecten lo que dicen. Eso lo hacen las muestras con
wazuh-logtest (tests/run_logtest.py) y las pruebas del README.
"""
import glob
import ipaddress
import os
import re
import sys
import xml.etree.ElementTree as ET

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Reglas de fabrica de Wazuh que las reglas propias usan como padre. Se comprobaron porque las reglas
# hijas disparan en el manager (ver las capturas de evidence/).
# Si aparece otra, hay que confirmarla en el manager y agregarla aca.
PADRES_DE_FABRICA = {5716, 80705, 80780, 80792, 92600}
# Regla de ejemplo que viene en el local_rules.xml original de Wazuh, no es parte del pack.
REGLAS_AJENAS = {100001}
# Raiz del honeypot (nivel 0): no necesita muestra propia.
SIN_MUESTRA = {100300}
# DNS publicos usados como direccion de ejemplo en comentarios. No son atacantes.
IPS_PERMITIDAS = {"1.1.1.1", "8.8.8.8", "8.8.4.4"}
EXTENSIONES_TEXTO = {".md", ".xml", ".txt", ".yml", ".yaml", ".json", ".py", ".cfg", ".rules",
                     ".example", ".sh", ".conf"}
CARPETAS_IGNORADAS = {".git", "_stage", "evidence", "__pycache__", ".pytest_cache"}

_RE_IP = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_RE_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")


def archivos_de_reglas(raiz=RAIZ):
    rutas = glob.glob(os.path.join(raiz, "honeypot", "*.xml")) + glob.glob(os.path.join(raiz, "rules", "*.xml"))
    # Orden de carga de Wazuh: alfabetico por nombre de archivo
    return sorted(rutas, key=os.path.basename)


def cargar_reglas(raiz=RAIZ):
    """Devuelve (reglas, errores). Cada regla: dict con id, level, archivo, orden, el y raiz_doc."""
    reglas, errores, orden = [], [], 0
    for ruta in archivos_de_reglas(raiz):
        rel = os.path.relpath(ruta, raiz)
        try:
            doc = ET.fromstring("<r>" + open(ruta, encoding="utf-8").read() + "</r>")
        except ET.ParseError as e:
            errores.append(f"{rel}: XML no valido ({e})")
            continue
        for el in doc.iter("rule"):
            reglas.append({"el": el, "archivo": rel, "orden": orden, "id": el.get("id")})
            orden += 1
    return reglas, errores


def _enteros(texto):
    return [int(x) for x in re.split(r"[,\s]+", (texto or "").strip()) if x.isdigit()]


def chequear_reglas(reglas, errores, avisos):
    por_id = {}
    for r in reglas:
        el, donde = r["el"], f"{r['archivo']} regla {r['id']}"
        if not (r["id"] or "").isdigit():
            errores.append(f"{r['archivo']}: regla sin id numerico")
            continue
        rid = int(r["id"])
        r["id"] = rid
        if rid in por_id:
            errores.append(f"{donde}: ID repetido (ya esta en {por_id[rid]['archivo']})")
        por_id[rid] = r
        if not 100000 <= rid <= 119999:
            errores.append(f"{donde}: fuera del rango de reglas propias (100000 a 119999)")
        nivel = el.get("level")
        if nivel is None or not nivel.isdigit() or not 0 <= int(nivel) <= 15:
            errores.append(f"{donde}: nivel invalido ({nivel})")
        desc = el.find("description")
        if desc is None or not (desc.text or "").strip():
            errores.append(f"{donde}: sin descripcion")
        for m in el.iterfind("mitre/id"):
            if not _RE_MITRE.match((m.text or "").strip()):
                errores.append(f"{donde}: ID de MITRE con formato invalido ({m.text})")
        freq, tf = el.get("frequency"), el.get("timeframe")
        if freq is not None or tf is not None:
            tiene_matched = any(el.find(t) is not None for t in ("if_matched_sid", "if_matched_group", "if_matched_regex"))
            # frequency exige timeframe; timeframe solo (correlacion con un evento previo, como 100370) es valido
            if (freq is not None and tf is None) or not tiene_matched:
                errores.append(f"{donde}: frequency necesita timeframe, y las dos necesitan un if_matched_*")
    for r in reglas:
        if not isinstance(r["id"], int):
            continue
        for tag in ("if_sid", "if_matched_sid"):
            for el in r["el"].iterfind(tag):
                for padre in _enteros(el.text):
                    if padre in por_id:
                        if por_id[padre]["orden"] > r["orden"]:
                            errores.append(
                                f"{r['archivo']} regla {r['id']}: su padre {padre} se carga DESPUES "
                                f"({por_id[padre]['archivo']}). Wazuh carga los archivos en orden alfabetico.")
                    elif padre not in PADRES_DE_FABRICA:
                        errores.append(f"{r['archivo']} regla {r['id']}: padre {padre} desconocido. Si es una regla "
                                       f"de fabrica, confirmarla en el manager y agregarla a PADRES_DE_FABRICA.")
        nivel = int(r["el"].get("level", "0") or 0)
        if nivel >= 3 and r["el"].find("mitre") is None and r["id"] not in REGLAS_AJENAS:
            avisos.append(f"{r['archivo']} regla {r['id']}: nivel {nivel} sin tecnica de MITRE")
    return por_id


def chequear_documentacion(por_id, raiz, errores):
    textos = {}
    for carpeta, readme in (("honeypot", os.path.join("honeypot", "README.md")), ("rules", "README.md")):
        ruta = os.path.join(raiz, readme)
        textos[carpeta] = open(ruta, encoding="utf-8", errors="replace").read() if os.path.exists(ruta) else ""
    for rid, r in por_id.items():
        if rid in REGLAS_AJENAS:
            continue
        carpeta = r["archivo"].split(os.sep)[0]
        if str(rid) not in textos.get(carpeta, ""):
            errores.append(f"{r['archivo']} regla {rid}: no aparece en el README que la documenta")


def chequear_muestras(por_id, raiz, errores):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import samples
    cubiertas, esperadas = set(), set()
    for ruta in sorted(glob.glob(os.path.join(raiz, "honeypot", "logtest_*_samples.txt"))):
        rel = os.path.relpath(ruta, raiz)
        try:
            casos = samples.parsear(open(ruta, encoding="utf-8").read(), rel)
        except ValueError as e:
            errores.append(str(e))
            continue
        for c in casos:
            esperadas.update(c.expect)
            cubiertas.update(c.expect)
            for i in c.expect + c.no:
                # 5760 y similares son reglas de fabrica que las muestras esperan a proposito
                if i not in por_id and not (i < 100000):
                    errores.append(f"{c.donde()}: la muestra menciona la regla {i}, que no existe")
    for rid, r in por_id.items():
        if r["archivo"].startswith("honeypot") and rid not in SIN_MUESTRA and rid not in cubiertas:
            errores.append(f"{r['archivo']} regla {rid}: ninguna muestra de logtest la espera (falta un test positivo)")


def ip_es_ajena(texto):
    """True si es una IP publica que no es de documentacion."""
    if texto in IPS_PERMITIDAS:
        return False
    try:
        ip = ipaddress.ip_address(texto)
    except ValueError:
        return False
    return ip.is_global


def chequear_ips(raiz, errores):
    for carpeta, dirs, archivos in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in CARPETAS_IGNORADAS]
        for nombre in archivos:
            if os.path.splitext(nombre)[1].lower() not in EXTENSIONES_TEXTO:
                continue
            ruta = os.path.join(carpeta, nombre)
            try:
                lineas = open(ruta, encoding="utf-8", errors="replace").read().splitlines()
            except OSError:
                continue
            for n, linea in enumerate(lineas, 1):
                for m in _RE_IP.finditer(linea):
                    partes = m.groups()
                    if any(int(p) > 255 for p in partes):
                        continue
                    ip = ".".join(partes)
                    if ip_es_ajena(ip):
                        errores.append(f"{os.path.relpath(ruta, raiz)}:{n}: IP publica de terceros ({ip}). "
                                       f"Usar un rango de documentacion o enmascararla (a.b.x.x).")


def comprobar(raiz=RAIZ):
    errores, avisos = [], []
    reglas, errs = cargar_reglas(raiz)
    errores += errs
    por_id = chequear_reglas(reglas, errores, avisos)
    chequear_documentacion(por_id, raiz, errores)
    chequear_muestras(por_id, raiz, errores)
    chequear_ips(raiz, errores)
    return por_id, errores, avisos


def main():
    por_id, errores, avisos = comprobar()
    for a in avisos:
        print("AVISO:", a)
    for e in errores:
        print("ERROR:", e)
    print(f"{len(por_id)} reglas revisadas, {len(errores)} errores, {len(avisos)} avisos.")
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
