"""Lector de los archivos de muestras (honeypot/logtest_*_samples.txt).

Cada evento de muestra va precedido de lineas de anotacion que empiezan con "#@":

    #@ expect=100353          regla que tiene que disparar (varias: "100367,100360" = cualquiera de ellas)
    #@ not=100364             regla que NO tiene que disparar
    #@ repeat=6               mandar el evento 6 veces; vale si la esperada dispara en alguna
    #@ session=corr           los casos con el mismo nombre comparten estado de logtest
    #@ setup                  caso de preparacion: se manda, no se evalua
    #@ needs=cdb              solo corre si se pide (hace falta la lista CDB registrada)

Un evento sin anotacion, una clave desconocida o una anotacion sin evento son errores: asi un
typo no puede dejar una muestra sin probar sin que nadie se entere.

Lo usan tests/run_logtest.py (wazuh-logtest real, en el manager) y tests/test_rules_ci.py
(modelo offline, en el CI).
"""
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

_CLAVES = {"expect", "not", "repeat", "session", "setup", "needs"}


@dataclass
class Caso:
    linea: str
    numero: int
    archivo: str
    expect: List[int] = field(default_factory=list)
    no: List[int] = field(default_factory=list)
    repeat: int = 1
    session: Optional[str] = None
    needs: Optional[str] = None
    setup: bool = False

    @property
    def evento(self):
        """El evento como dict si es JSON; None si es una linea de syslog u otro formato."""
        try:
            e = json.loads(self.linea)
        except ValueError:
            return None
        return e if isinstance(e, dict) else None

    def donde(self):
        return f"{self.archivo}:{self.numero}"


def _ids(valor, donde):
    try:
        return [int(x) for x in valor.split(",") if x]
    except ValueError:
        raise ValueError(f"{donde}: ids invalidos en '{valor}'")


def parsear(texto, archivo="<memoria>"):
    casos, pend = [], None
    for n, crudo in enumerate(texto.splitlines(), 1):
        s = crudo.strip()
        if not s:
            continue
        if s.startswith("#@"):
            pend = pend or {"expect": [], "no": [], "repeat": 1, "session": None,
                            "needs": None, "setup": False, "n": n}
            for tok in s[2:].split():
                clave, _, valor = tok.partition("=")
                donde = f"{archivo}:{n}"
                if clave not in _CLAVES:
                    raise ValueError(f"{donde}: anotacion desconocida '{clave}'")
                if clave == "expect":
                    pend["expect"] += _ids(valor, donde)
                elif clave == "not":
                    pend["no"] += _ids(valor, donde)
                elif clave == "repeat":
                    if not valor.isdigit() or int(valor) < 1:
                        raise ValueError(f"{donde}: repeat tiene que ser un entero positivo")
                    pend["repeat"] = int(valor)
                elif clave == "setup":
                    pend["setup"] = True
                else:
                    pend[clave] = valor or None
            continue
        if s.startswith("#"):
            continue
        if pend is None:
            raise ValueError(f"{archivo}:{n}: evento sin anotaciones '#@' (no se probaria nunca)")
        if not (pend["expect"] or pend["no"] or pend["setup"]):
            raise ValueError(f"{archivo}:{pend['n']}: el caso no tiene expect, not ni setup")
        casos.append(Caso(linea=s, numero=n, archivo=archivo, expect=pend["expect"], no=pend["no"],
                          repeat=pend["repeat"], session=pend["session"], needs=pend["needs"],
                          setup=pend["setup"]))
        pend = None
    if pend is not None:
        raise ValueError(f"{archivo}:{pend['n']}: anotaciones sin evento a continuacion")
    return casos


def agrupar(casos):
    """Devuelve listas de casos que corren juntos: una por sesion con nombre, y una por caso
    suelto. Respeta el orden del archivo."""
    grupos, por_sesion = [], {}
    for c in casos:
        if c.session is None:
            grupos.append([c])
        elif c.session in por_sesion:
            por_sesion[c.session].append(c)
        else:
            por_sesion[c.session] = [c]
            grupos.append(por_sesion[c.session])
    return grupos


def evaluar(caso, obtenidos):
    """obtenidos: id de regla de cada envio del caso (None si no disparo ninguna).
    Devuelve (ok, detalle)."""
    if caso.setup:
        return True, "preparacion"
    vistos = ", ".join(str(o) for o in obtenidos)
    if caso.expect:
        if caso.repeat == 1:
            ok = obtenidos[0] in caso.expect
        else:
            ok = any(o in caso.expect for o in obtenidos)
        if not ok:
            return False, f"esperaba {caso.expect}, obtuvo [{vistos}]"
    for r in caso.no:
        if r in obtenidos:
            return False, f"no debia disparar {r}, obtuvo [{vistos}]"
    return True, f"[{vistos}]"
