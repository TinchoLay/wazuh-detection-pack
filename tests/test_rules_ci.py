"""Tests del CI del pack. No necesitan Wazuh.

Tres capas, de menos a mas fe:
1. check_rules.py: chequeos estaticos de las reglas, la documentacion, las muestras y las IPs.
2. El modelo offline (rule_model.py) contra las muestras de un solo evento. Es una aproximacion.
3. El runner de logtest (run_logtest.py), probado con un logtest FALSO que usa el modelo. Eso
   prueba el programa (alineacion, repeticiones, sesiones, informe), no a Wazuh.
Lo que de verdad prueba las reglas es correr tests/run_logtest.py en el manager.
"""
import json
import os
import subprocess
import sys
import textwrap

import pytest

import check_rules
import rule_model
import run_logtest
import samples

RAIZ = check_rules.RAIZ
ARCHIVOS_MUESTRAS = sorted(
    os.path.join(RAIZ, "honeypot", f) for f in os.listdir(os.path.join(RAIZ, "honeypot"))
    if f.startswith("logtest_") and f.endswith("_samples.txt"))


def _casos():
    out = []
    for ruta in ARCHIVOS_MUESTRAS:
        out += samples.parsear(open(ruta, encoding="utf-8").read(), os.path.relpath(ruta, RAIZ))
    return out


# --- 1. Chequeos estaticos --------------------------------------------------------

def test_el_repo_pasa_los_chequeos_estaticos():
    _, errores, _ = check_rules.comprobar()
    assert errores == []


def _repo_minimo(tmp_path, xml, readme="100900 100901", muestras=""):
    (tmp_path / "honeypot").mkdir()
    (tmp_path / "rules").mkdir()
    (tmp_path / "honeypot" / "a_rules.xml").write_text(xml, encoding="utf-8")
    (tmp_path / "honeypot" / "README.md").write_text(readme, encoding="utf-8")
    (tmp_path / "README.md").write_text("", encoding="utf-8")
    (tmp_path / "honeypot" / "logtest_x_samples.txt").write_text(muestras, encoding="utf-8")
    return str(tmp_path)


def test_detecta_id_repetido_y_padre_inexistente(tmp_path):
    xml = """<group name="x">
      <rule id="100900" level="3"><decoded_as>json</decoded_as><description>a</description></rule>
      <rule id="100900" level="3"><if_sid>999999</if_sid><description>b</description></rule>
    </group>"""
    _, errores, _ = check_rules.comprobar(_repo_minimo(tmp_path, xml))
    texto = "\n".join(errores)
    assert "ID repetido" in texto
    assert "padre 999999 desconocido" in texto


def test_detecta_padre_que_carga_despues(tmp_path):
    raiz = _repo_minimo(tmp_path, """<group name="x">
      <rule id="100900" level="3"><if_sid>100901</if_sid><description>hija</description></rule>
      <rule id="100901" level="3"><decoded_as>json</decoded_as><description>padre</description></rule>
    </group>""")
    _, errores, _ = check_rules.comprobar(raiz)
    assert any("se carga DESPUES" in e for e in errores)


def test_detecta_xml_roto_nivel_invalido_y_mitre_malo(tmp_path):
    raiz = _repo_minimo(tmp_path, """<group name="x">
      <rule id="100900" level="99"><decoded_as>json</decoded_as><description>a</description>
        <mitre><id>T12</id></mitre></rule>
    </group>""")
    _, errores, _ = check_rules.comprobar(raiz)
    texto = "\n".join(errores)
    assert "nivel invalido" in texto and "MITRE" in texto
    (tmp_path / "honeypot" / "b_rules.xml").write_text("<group><!-- a -- b --></group>", encoding="utf-8")
    _, errores, _ = check_rules.comprobar(raiz)
    assert any("XML no valido" in e for e in errores)


def test_detecta_frecuencia_incompleta(tmp_path):
    raiz = _repo_minimo(tmp_path, """<group name="x">
      <rule id="100900" level="3"><decoded_as>json</decoded_as><description>a</description></rule>
      <rule id="100901" level="5" frequency="5"><if_matched_sid>100900</if_matched_sid><description>b</description></rule>
    </group>""")
    _, errores, _ = check_rules.comprobar(raiz)
    assert any("frequency necesita timeframe" in e for e in errores)


def test_detecta_regla_sin_muestra_y_sin_documentar(tmp_path):
    raiz = _repo_minimo(tmp_path, """<group name="x">
      <rule id="100900" level="3"><decoded_as>json</decoded_as><description>a</description></rule>
    </group>""", readme="nada")
    _, errores, _ = check_rules.comprobar(raiz)
    texto = "\n".join(errores)
    assert "no aparece en el README" in texto
    assert "ninguna muestra de logtest la espera" in texto


def test_detecta_ips_de_terceros(tmp_path):
    # La IP publica se arma por partes: este archivo tambien lo revisa check_rules.
    ajena = ".".join(["80", "94", "92", "179"])
    (tmp_path / "nota.md").write_text(f"visto en {ajena} y en 80.94.x.x, 203.0.113.9, 192.0.2.1, "
                                      "10.0.0.5, 172.31.33.195, 8.8.8.8 y 999.1.1.1", encoding="utf-8")
    errores = []
    check_rules.chequear_ips(str(tmp_path), errores)
    assert len(errores) == 1 and ajena in errores[0]


# --- 2. Parser de muestras y modelo offline --------------------------------------

def test_parser_rechaza_muestras_mal_formadas():
    with pytest.raises(ValueError, match="sin anotaciones"):
        samples.parsear('{"a": 1}')
    with pytest.raises(ValueError, match="desconocida"):
        samples.parsear('#@ espect=1\n{"a": 1}')
    with pytest.raises(ValueError, match="sin evento"):
        samples.parsear("#@ expect=1\n")
    with pytest.raises(ValueError, match="no tiene expect"):
        samples.parsear('#@ session=x\n{"a": 1}')
    with pytest.raises(ValueError, match="repeat"):
        samples.parsear('#@ repeat=0 expect=1\n{"a": 1}')


def test_parser_lee_anotaciones_y_agrupa():
    casos = samples.parsear('#@ expect=1,2 not=3\n{"a":1}\n\n#@ session=s repeat=3 expect=4\n{"a":2}\n'
                            '#@ session=s expect=5\n{"a":3}\n#@ setup\n{"a":4}\n')
    assert casos[0].expect == [1, 2] and casos[0].no == [3]
    assert casos[1].repeat == 3 and casos[1].session == "s"
    assert casos[3].setup
    assert [len(g) for g in samples.agrupar(casos)] == [1, 2, 1]


def test_evaluar():
    c = samples.parsear('#@ expect=7 not=9\n{"a":1}')[0]
    assert samples.evaluar(c, [7])[0]
    assert not samples.evaluar(c, [8])[0]
    assert not samples.evaluar(c, [9])[0]
    r = samples.parsear('#@ repeat=3 expect=7\n{"a":1}')[0]
    assert samples.evaluar(r, [1, 2, 7])[0]
    assert not samples.evaluar(r, [1, 2, 3])[0]


def _modelables():
    return [c for c in _casos() if not (c.session or c.needs or c.repeat > 1) and c.evento is not None]


def test_el_modelo_coincide_con_las_muestras_de_un_evento():
    modelo = rule_model.Modelo.desde_carpeta(os.path.join(RAIZ, "honeypot"))
    casos = _modelables()
    assert len(casos) >= 30, "se estan salteando demasiados casos: revisar las anotaciones"
    malos = []
    for c in casos:
        ok, detalle = samples.evaluar(c, [modelo.clasificar(c.evento)])
        if not ok:
            malos.append(f"{c.donde()}: {detalle}")
    assert malos == []


def test_el_modelo_no_inventa_reglas_de_frecuencia():
    modelo = rule_model.Modelo.desde_carpeta(os.path.join(RAIZ, "honeypot"))
    # una entrada aceptada de un cliente Go cae en 100353; 100354 (frecuencia) no se evalua aca
    ev = {"honeypot_event": "ssh_connection", "ip": "203.0.113.1", "resultado": "autenticado_sin_shell",
          "banner": "SSH-2.0-Go"}
    assert modelo.clasificar(ev) == 100353


def test_el_modelo_baja_por_el_arbol_y_gana_la_primera_hermana(tmp_path):
    f = tmp_path / "r.xml"
    f.write_text("""<group name="x">
      <rule id="100900" level="0"><decoded_as>json</decoded_as><field name="t">.+</field><description>raiz</description></rule>
      <rule id="100901" level="3"><if_sid>100900</if_sid><field name="a" type="pcre2">^1$</field><description>h1</description></rule>
      <rule id="100902" level="3"><if_sid>100900</if_sid><field name="a" type="pcre2">^[12]$</field><description>h2</description></rule>
      <rule id="100903" level="5"><if_sid>100901</if_sid><field name="b" type="pcre2">^x$</field><description>nieta</description></rule>
    </group>""", encoding="utf-8")
    m = rule_model.Modelo([str(f)])
    assert m.clasificar({"t": "e", "a": "1", "b": "x"}) == 100903
    assert m.clasificar({"t": "e", "a": "1", "b": "y"}) == 100901
    assert m.clasificar({"t": "e", "a": "2"}) == 100902
    assert m.clasificar({"t": "e", "a": "3"}) == 100900
    assert m.clasificar({"otro": "e"}) is None


# --- 3. El runner de logtest, con un logtest falso --------------------------------

FALSO = textwrap.dedent('''
    import json, os, sys
    sys.path.insert(0, {tests!r})
    import rule_model
    modelo = rule_model.Modelo.desde_carpeta({honeypot!r})
    print("Starting wazuh-logtest v4.14.8")
    print("Type one log per line")
    for linea in sys.stdin:
        linea = linea.strip()
        if not linea:
            continue
        print()
        print("**Phase 1: Completed pre-decoding.")
        print("\\tfull event: " + repr(linea))
        print()
        print("**Phase 2: Completed decoding.")
        print("\\tname: 'json'")
        try:
            regla = modelo.clasificar(json.loads(linea))
        except ValueError:
            regla = None
        if regla is not None:
            r = modelo.reglas[regla]
            print()
            print("**Phase 3: Completed filtering (rules).")
            print("\\tid: '%d'" % regla)
            print("\\tlevel: '%d'" % r.level)
            print("\\tdescription: 'x'")
            print("\\tfiredtimes: '1'")
            if r.level >= 3:
                print("**Alert to be generated.")
''')


@pytest.fixture
def logtest_falso(tmp_path):
    ruta = tmp_path / "fake_logtest"
    cuerpo = FALSO.format(tests=os.path.join(RAIZ, "tests"), honeypot=os.path.join(RAIZ, "honeypot"))
    ruta.write_text(f"#!{sys.executable}\n" + cuerpo, encoding="utf-8")
    ruta.chmod(0o755)
    return str(ruta)


SALIDA_CANONICA = """Starting wazuh-logtest v4.14.8
Type one log per line

**Phase 1: Completed pre-decoding.
\tfull event: '{"a": 1}'

**Phase 2: Completed decoding.
\tname: 'json'

**Phase 3: Completed filtering (rules).
\tid: '100353'
\tlevel: '7'
\tdescription: 'Honeypot: x'
\tgroups: '['honeypot']'
\tfiredtimes: '1'
**Alert to be generated.

**Phase 1: Completed pre-decoding.
\tfull event: 'Oct 27 sshd: nada'

**Phase 2: Completed decoding.
\tname: 'sshd'
"""


def test_parsear_salida_de_logtest():
    assert run_logtest.parsear_salida(SALIDA_CANONICA) == [100353, None]
    assert run_logtest.parsear_salida("") == []


def test_el_runner_alinea_repeticiones_sesiones_y_setup(logtest_falso):
    casos = samples.parsear(textwrap.dedent('''
        #@ expect=100351
        {"honeypot_event": "ssh_connection", "ip": "203.0.113.1", "resultado": "sin_banner"}
        #@ session=s setup repeat=2
        {"honeypot_event": "ssh_connection", "ip": "203.0.113.2", "resultado": "login_fallido"}
        #@ session=s expect=100353
        {"honeypot_event": "ssh_connection", "ip": "203.0.113.2", "resultado": "autenticado_sin_shell", "banner": "SSH-2.0-Go"}
        #@ repeat=3 expect=100340
        {"honeypot_event": "http_request", "ip": "203.0.113.3", "method": "GET", "path": "/"}
        #@ needs=cdb expect=100330
        {"honeypot_event": "ssh_connection", "ip": "203.0.113.4"}
    '''))
    fallos, salteados, total, reporte = run_logtest.correr(casos, logtest_falso)
    assert (fallos, salteados, total) == (0, 1, 3), reporte
    assert any("SALTEADO" in r for r in reporte)


def test_el_runner_informa_un_fallo_real(logtest_falso):
    casos = samples.parsear(textwrap.dedent('''
        #@ expect=100354 session=go repeat=6
        {"honeypot_event": "ssh_connection", "ip": "203.0.113.5", "resultado": "autenticado_sin_shell", "banner": "SSH-2.0-Go"}
        #@ expect=100999
        {"honeypot_event": "ssh_connection", "ip": "203.0.113.6", "resultado": "sin_banner"}
    '''))
    # El logtest falso no evalua frecuencia, asi que 100354 no aparece: el runner tiene que decirlo.
    fallos, _, total, reporte = run_logtest.correr(casos, logtest_falso)
    assert fallos == 2 and total == 2
    assert sum("FALLO" in r for r in reporte) == 2


def _ejecutable(ruta):
    ruta.chmod(0o755)
    return str(ruta)


def test_el_runner_avisa_si_no_puede_alinear(tmp_path):
    roto = tmp_path / "roto"
    roto.write_text(f"#!{sys.executable}\nimport sys\nsys.stdin.read()\nprint('algo raro')\n", encoding="utf-8")
    casos = samples.parsear('#@ expect=1\n{"a": 1}')
    fallos, _, _, reporte = run_logtest.correr(casos, _ejecutable(roto))
    assert fallos == 1 and "no se pueden alinear" in reporte[0]


def test_main_de_punta_a_punta_con_logtest_falso(logtest_falso, tmp_path, capsys):
    ok = tmp_path / "ok.txt"
    ok.write_text('#@ expect=100351\n{"honeypot_event": "ssh_connection", "ip": "203.0.113.1", "resultado": "sin_banner"}\n')
    assert run_logtest.main([str(ok), "--logtest", logtest_falso]) == 0
    assert "1/1 casos bien" in capsys.readouterr().out
    mal = tmp_path / "mal.txt"
    mal.write_text('#@ expect=100999\n{"honeypot_event": "ssh_connection", "ip": "203.0.113.1", "resultado": "sin_banner"}\n')
    assert run_logtest.main([str(mal), "--logtest", logtest_falso]) == 1


# --- Capa ATT&CK ------------------------------------------------------------------

def test_la_capa_de_attck_esta_al_dia(tmp_path):
    salida = tmp_path / "layer.json"
    subprocess.run([sys.executable, os.path.join(RAIZ, "navigator", "build_layer.py"),
                    os.path.join(RAIZ, "rules", "local_rules.xml"), str(salida)],
                   check=True, capture_output=True, cwd=RAIZ)
    nueva = json.loads(salida.read_text(encoding="utf-8"))
    actual = json.loads(open(os.path.join(RAIZ, "navigator", "wazuh-detection-pack-layer.json"),
                             encoding="utf-8").read())
    assert nueva == actual, "navigator/wazuh-detection-pack-layer.json no coincide con las reglas: regenerarla"
