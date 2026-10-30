"""Modelo OFFLINE de las reglas del honeypot. Es una aproximacion, NO es wazuh-logtest.

Para que sirve: que el CI pueda comprobar, sin un manager de Wazuh, que cada evento de muestra
cae en la regla esperada. Para que NO sirve: confirmar que Wazuh se comporta asi. La prueba de
verdad es tests/run_logtest.py en el manager. Si los dos discrepan, uno de los dos esta mal y hay
que averiguar cual (el modelo es el sospechoso).

Que modela (un solo evento, sin estado):
- reglas raiz (decoded_as json) y reglas hijas por if_sid, en el orden en que Wazuh carga los
  archivos (alfabetico por nombre) y dentro de cada archivo;
- condiciones <field> con regex pcre2 o OSRegex (de este ultimo solo traduce "\\." a "."),
  incluidos campos anidados del JSON ("virustotal.maliciosos");
- gana la PRIMERA hermana que coincide, y se baja por sus hijas.

Que NO modela, y por eso esas reglas nunca coinciden aca: frecuencia, if_matched_*, listas CDB,
y cualquier etiqueta que no este en SOPORTADAS. Los casos de muestra que dependen de eso llevan
"repeat", "session" o "needs", y el CI no los evalua con este modelo.
"""
import glob
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

SOPORTADAS = {"if_sid", "field", "decoded_as"}
NEUTRAS = {"description", "group", "mitre", "same_field", "info"}


class Regla:
    def __init__(self, el, archivo, orden):
        self.id = int(el.get("id"))
        self.level = int(el.get("level", "0"))
        self.archivo = archivo
        self.orden = orden
        self.if_sid = []
        self.campos = []          # (nombre, regex compilado)
        self.decoded_as = None
        self.modelable = True
        if el.get("frequency") or el.get("timeframe"):
            self.modelable = False
        for hijo in el:
            t = hijo.tag
            if t == "if_sid":
                self.if_sid += [int(x) for x in re.split(r"[,\s]+", (hijo.text or "").strip()) if x]
            elif t == "decoded_as":
                self.decoded_as = (hijo.text or "").strip()
            elif t == "field":
                self.campos.append((hijo.get("name"), _compilar(hijo.text or "", hijo.get("type"))))
            elif t in NEUTRAS:
                continue
            else:
                self.modelable = False   # if_matched_*, if_group, list, srcip, regex, match...


def _compilar(patron, tipo):
    if tipo != "pcre2":
        patron = patron.replace("\\.", ".")      # en OSRegex "\." es "cualquier caracter"
    return re.compile(patron)


def _aplanar(valor, prefijo=""):
    plano = {}
    if isinstance(valor, dict):
        for k, v in valor.items():
            plano.update(_aplanar(v, f"{prefijo}{k}."))
    else:
        plano[prefijo[:-1]] = "null" if valor is None else str(valor)
    return plano


class Modelo:
    def __init__(self, rutas):
        self.reglas: Dict[int, Regla] = {}
        orden = 0
        for ruta in sorted(rutas, key=os.path.basename):
            raiz = ET.fromstring("<r>" + open(ruta, encoding="utf-8").read() + "</r>")
            for el in raiz.iter("rule"):
                r = Regla(el, ruta, orden)
                orden += 1
                self.reglas[r.id] = r
        self.hijos: Dict[int, List[Regla]] = {}
        self.raices: List[Regla] = []
        for r in sorted(self.reglas.values(), key=lambda x: x.orden):
            if r.if_sid:
                for padre in r.if_sid:
                    self.hijos.setdefault(padre, []).append(r)
            elif r.decoded_as:
                self.raices.append(r)

    @classmethod
    def desde_carpeta(cls, carpeta):
        return cls(glob.glob(os.path.join(carpeta, "*.xml")))

    def _coincide(self, r, plano, es_json):
        if not r.modelable:
            return False
        if r.decoded_as == "json" and not es_json:
            return False
        for nombre, rx in r.campos:
            if nombre not in plano or not rx.search(plano[nombre]):
                return False
        return True

    def _bajar(self, r, plano):
        for h in self.hijos.get(r.id, []):
            if self._coincide(h, plano, True):
                return self._bajar(h, plano)
        return r.id

    def clasificar(self, evento: dict) -> Optional[int]:
        plano = _aplanar(evento)
        for r in self.raices:
            if self._coincide(r, plano, True):
                return self._bajar(r, plano)
        return None
