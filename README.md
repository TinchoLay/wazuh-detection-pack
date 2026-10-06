# Wazuh Detection Pack | Linux detection engineering lab

**[English](#english) | [Español](#español)**

---

## English

A personal home lab for learning detection engineering on Wazuh, end to end. I read what an adversary does, turn it into a rule, check that the rule fires, check that it stays quiet on normal activity, and write down how someone could evade it.

This is lab work, not production or client work, and it has no affiliation with Wazuh.

Status: phase 1 is done (infrastructure and 3 custom rules validated). Phase 2, rules driven by a threat group, has not started. See the [roadmap](#roadmap).

### What this project shows

- A working Wazuh 4.14.8 deployment on AWS with a monitored Ubuntu endpoint (auditd telemetry).
- Three custom Wazuh rules mapped to MITRE ATT&CK, each with a positive test, a negative test and a documented evasion.
- Two mistakes I caught by checking claims against the primary source: a coverage gap in my own rule and a naming mismatch between Wazuh and ATT&CK (see [Findings](#findings)).
- What each rule misses and where it gives false positives.

### Lab architecture

```
 Endpoint (Ubuntu 24.04)                         Server (Ubuntu 24.04)
 auditd + Wazuh agent  --- 1514/1515 (private IP) --->  Wazuh 4.14.8 all-in-one
 endpoint-linux-01                                      manager + indexer + dashboard
                                                                 ^
                                              dashboard (443) and SSH (22): my ISP's /24 only
```

| Component | Detail |
| --- | --- |
| Cloud | AWS, us-east-1, paid with account credit |
| Server | Ubuntu Server 24.04 LTS, t3.xlarge (4 vCPU, 16 GB), 50 GiB gp3 |
| Wazuh | 4.14.8 all-in-one, installed with the official installation assistant |
| Endpoint | Ubuntu Server 24.04 LTS, Wazuh agent 4.14.8, agent name `endpoint-linux-01`, small instance (t3.small class), 20 GiB gp3 |
| Agent to server | Over the server's **private IP**, so it does not change when instances are stopped and started |
| Telemetry | Linux Audit (`auditd`), `execve` syscalls of my user, read by the agent from `/var/log/audit/audit.log` |
| Cost guard | AWS Budget with an email alert, set before launching anything |

#### Network decisions (security group)

- SSH (22) and HTTPS (443): only from my ISP's `/24` block. My public IP changed between three different addresses of the same block in under two hours, so a single `/32` kept locking me out. This is a conscious trade-off: less strict than `/32`, far stricter than `0.0.0.0/0`.
- 1514-1515 (agents): only from the security group itself.
- Never `0.0.0.0/0`.

### Rules

All rules chain from Wazuh's stock rule **80792** ("Audit: Command"), which classifies any command run under the `audit-wazuh-c` key. That base rule has no MITRE mapping and does not tell a harmless `ls` from something suspicious, so the custom rules add that context.

| ID | Level | What it detects | ATT&CK |
| --- | --- | --- | --- |
| 100100 | 8 | `whoami`, `id`, `w`, `who` (user discovery) | T1033 |
| 100101 | 10 | `cp`, `mv` or `ln` on those binaries (staging a copy to rename it) | T1036.003 |
| 100102 | 7 | Any binary executed from `/tmp`, `/var/tmp` or `/dev/shm` | T1036.003 |

Full file: [`rules/local_rules.xml`](rules/local_rules.xml).

<details>
<summary>Show the three rules</summary>

```xml
<group name="local,audit,">
  <rule id="100100" level="8">
    <if_sid>80792</if_sid>
    <field name="audit.command" type="pcre2">^(whoami|id|w|who)$</field>
    <description>Audit: User discovery command executed: $(audit.command) by auid $(audit.auid)</description>
    <mitre>
      <id>T1033</id>
    </mitre>
    <group>audit_command,discovery,</group>
  </rule>
</group>

<group name="local,audit,">
  <rule id="100101" level="10">
    <if_sid>80792</if_sid>
    <field name="audit.command" type="pcre2">^(cp|mv|ln)$</field>
    <regex type="pcre2">\sa[1-9]="/usr/bin/(whoami|id|who|w)"</regex>
    <description>Audit: Binary used for user discovery copied, moved or linked: $(audit.execve.a1) $(audit.execve.a2)</description>
    <mitre>
      <id>T1036.003</id>
    </mitre>
    <group>audit_command,defense_evasion,</group>
  </rule>
</group>

<group name="local,audit,">
  <rule id="100102" level="7">
    <if_sid>80792</if_sid>
    <field name="audit.exe" type="pcre2">^/(tmp|var/tmp|dev/shm)/</field>
    <description>Audit: Binary executed from a temporary directory: $(audit.exe)</description>
    <mitre>
      <id>T1036.003</id>
    </mitre>
    <group>audit_command,defense_evasion,</group>
  </rule>
</group>
```

</details>

#### Design choices

- Custom rule IDs in the 100000-119999 range, so they never collide with stock rules.
- Level 8 for 100100, not 12: a lone `whoami` is a hint, not proof of compromise.
- `auid` instead of `uid` in the audit rule: `auid` is the login user and survives `sudo`, so privilege escalation does not hide the command.
- Workflow before every change: back up `local_rules.xml`, validate with `/var/ossec/bin/wazuh-analysisd -t`, only then restart the manager.

### Validation results

| Test | Result |
| --- | --- |
| `whoami`, `id` | Fires 100100 |
| `ls`, `date` | Does not fire. Control: the base rule 80792 did fire, so the events reached the server |
| `who`, `w` | Fires 100100 (after extending the rule, see Findings) |
| `cp /usr/bin/id /tmp/idc` | Fires 100101 |
| `cp /etc/hostname /tmp/h` | Does not fire (negative test) |
| `cp /usr/bin/whoami /tmp/wm`, then `/tmp/wm` | Does **not** fire 100100 (evasion). Fires 100102 |

A negative result only counts when a control proves the event arrived. Every "does not fire" above was checked against rule 80792.

### Findings

1. **Coverage gap in my first version.** Rule 100100 v1 covered only `whoami` and `id`. The official T1033 page also lists `w` and `who` for Linux. v2 includes them.
2. **Renaming defeats a name-based rule.** In the alert for `/tmp/wm`, `audit.command` is `wm` while `audit.exe` is `/tmp/wm`. A filter on the command name misses a renamed copy; the path does not. That is what 100102 uses.
3. **Wazuh and ATT&CK disagree on names for the same ID.**

   | | Wazuh 4.14.8 (alert) | ATT&CK (official page, v19) |
   | --- | --- | --- |
   | T1036.003 name | Rename System Utilities | Rename Legitimate Utilities |
   | Tactic | Defense Evasion | Stealth (TA0005) |

   The ID matches, so the mapping is right. My hypothesis, **not verified**, is that Wazuh ships an older ATT&CK dataset. Practical rule: map by ID, never by name, and check the primary source.

### Known limitations

- 100100 flags `id` every time, and scripts and admins run it constantly. In a real environment this is noisy.
- 100101 detects the staging step (the copy), not the use of the renamed binary.
- 100102 has false positives (installers, `snap`, legitimate scripts) and is evaded by executing from another folder.
- No rule uses `tty` or `ppid` yet to separate interactive use from scripting.
- Tested on a single endpoint, only with my own commands. False-positive rate is not measured.

### Hypotheses not tested yet

| Maneuver | Rule that should see it | Status |
| --- | --- | --- |
| Copy to `/home/ubuntu`, run from there | Only 100101 (the copy) | Hypothesis |
| `cd /usr/bin; cp whoami /tmp/x` (relative path) | 100101 probably not (regex expects `/usr/bin/...`); 100102 yes when run from `/tmp` | Hypothesis |
| `cat /usr/bin/whoami > /tmp/x` then `chmod +x` | 100101 no; 100102 yes when run from `/tmp` | Hypothesis |
| Same, but running it from `/home/ubuntu` | None (full evasion) | Hypothesis |
| Legitimate `#!` script run from `/tmp` | 100102 (false positive). Check which `exe` auditd records | To measure |
| `echo $USER` | Probably nothing (shell builtin, no `execve`) | Hypothesis |

### How to reproduce

1. **AWS.** Create a budget alert first. Launch the standard **Ubuntu Server 24.04 LTS** AMI from Canonical (avoid the variants with SQL Server, Ubuntu Pro or Deep Learning, which add cost or software you do not need). Put both instances in one security group with the rules above.
2. **Server.** Official quickstart (all-in-one):
   ```bash
   curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
   ```
   Save the generated admin password somewhere safe. If `apt` returns 404 errors on a fresh instance, run `sudo apt update` first.
3. **Endpoint agent.** Use the dashboard's "Deploy new agent" wizard (Linux, DEB amd64) with the server's **private IP**.
4. **auditd on the endpoint.**
   ```bash
   sudo apt update && sudo apt -y install auditd
   sudo systemctl enable --now auditd
   sudo tee /etc/audit/rules.d/wazuh-cmds.rules > /dev/null <<'EOF'
   -a always,exit -F arch=b32 -S execve -F auid=1000 -F auid!=-1 -k audit-wazuh-c
   -a always,exit -F arch=b64 -S execve -F auid=1000 -F auid!=-1 -k audit-wazuh-c
   EOF
   sudo augenrules --load
   sudo auditctl -l
   ```
   Check your UID first with `id` (the rules assume 1000).
5. **Tell the agent to read the audit log.** If `grep audit /var/ossec/etc/ossec.conf` returns nothing, add this block next to the other `<localfile>` entries and restart the agent:
   ```xml
   <localfile>
     <log_format>audit</log_format>
     <location>/var/log/audit/audit.log</location>
   </localfile>
   ```
6. **Rules on the server.** Append the rules to `/var/ossec/etc/rules/local_rules.xml`, then `sudo /var/ossec/bin/wazuh-analysisd -t` and `sudo systemctl restart wazuh-manager`.
7. **Test** on the endpoint and look for `rule.id:(100100 or 100101 or 100102)` in Threat Hunting.

### Troubleshooting notes

- **SSH `Connection timed out`:** the security group did not match my current public IP. My ISP rotates addresses, so I opened the provider's `/24` for SSH and HTTPS only.
- **`UNPROTECTED PRIVATE KEY FILE` on Windows:** fixed with `icacls ... /inheritance:r` and `/grant:r`, leaving read access to my user only.
- **`apt` 404 on a fresh instance:** stale package index. `sudo apt update` fixed it.
- **A rule file edited by hand in nano got damaged:** discarded the unsaved changes, and kept timestamped backups from then on.

### Cost control

Stop both instances after each session (a stopped instance does not bill compute, but the disk keeps billing), watch the budget alert, and terminate instances and volumes when the project ends.

### Security hygiene

- The `.pem` key never goes into a repository (`.gitignore` covers `*.pem`).
- No passwords, account IDs or public IPs in this repo.
- Backup before editing rule files, and validate before restarting.

### How I worked

I used an AI assistant as a guide while building this and treated its output as a claim to verify. Where it mattered I checked the primary source (Wazuh docs, attack.mitre.org). That check is what surfaced the missing `w`/`who` coverage and the naming mismatch above.

### Roadmap

- [x] Wazuh server and Linux endpoint with auditd telemetry
- [x] Three custom rules with positive, negative and evasion tests
- [ ] Run the untested hypotheses above and document the results
- [ ] Pick a threat group relevant to Linux and extract techniques from public reports
- [ ] 8 to 10 techniques, 10 to 12 rules, each with a positive test, a false-positive test and an evasion note
- [ ] Coverage matrix in ATT&CK Navigator
- [ ] Convert 2 or 3 rules to Sigma
- [ ] Windows endpoint with Sysmon (phase 2)
- [ ] Per-rule write-up in English

### Evidence

Screenshots live in [`evidence/`](evidence/):
`100100-whoami.png`, `100101-cp.png`, `100102-tmp-wm.png`, `control-80792-wm.png`.

### Sources

- [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh: Monitoring system calls, configuration](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html)
- [Wazuh PoC: Monitoring execution of malicious commands](https://documentation.wazuh.com/current/proof-of-concept-guide/audit-commands-run-by-user.html) (the auditd approach is adapted from here)
- [MITRE ATT&CK T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [MITRE ATT&CK T1036.003: Rename Legitimate Utilities](https://attack.mitre.org/techniques/T1036/003/)

### License

MIT.

---

## Español

Un laboratorio personal para aprender ingeniería de detección en Wazuh, de punta a punta. Leo qué hace un adversario, lo convierto en una regla, compruebo que dispara, compruebo que se calla con actividad normal y dejo escrito cómo alguien podría evadirla.

Esto es trabajo de laboratorio, no de producción ni de clientes, y no tiene relación con Wazuh.

Estado: la fase 1 está terminada (infraestructura y 3 reglas propias validadas). La fase 2, con reglas guiadas por un grupo de amenaza, todavía no empezó. Ver la [hoja de ruta](#hoja-de-ruta).

### Qué muestra este proyecto

- Un despliegue funcional de Wazuh 4.14.8 en AWS con un endpoint Ubuntu monitoreado (telemetría de auditd).
- Tres reglas propias de Wazuh mapeadas a MITRE ATT&CK, cada una con prueba positiva, prueba negativa y una evasión documentada.
- Dos errores que detecté al contrastar afirmaciones con la fuente primaria: un hueco de cobertura en mi propia regla y una diferencia de nombres entre Wazuh y ATT&CK (ver [Hallazgos](#hallazgos)).
- Qué se le escapa a cada regla y dónde da falsos positivos.

### Arquitectura del lab

```
 Endpoint (Ubuntu 24.04)                         Servidor (Ubuntu 24.04)
 auditd + agente Wazuh --- 1514/1515 (IP privada) --->  Wazuh 4.14.8 all-in-one
 endpoint-linux-01                                      manager + indexer + dashboard
                                                                 ^
                                  dashboard (443) y SSH (22): solo el /24 de mi proveedor
```

| Componente | Detalle |
| --- | --- |
| Nube | AWS, us-east-1, pagado con crédito de la cuenta |
| Servidor | Ubuntu Server 24.04 LTS, t3.xlarge (4 vCPU, 16 GB), 50 GiB gp3 |
| Wazuh | 4.14.8 all-in-one, instalado con el asistente oficial |
| Endpoint | Ubuntu Server 24.04 LTS, agente Wazuh 4.14.8, nombre `endpoint-linux-01`, instancia chica (clase t3.small), 20 GiB gp3 |
| Agente al servidor | Por la **IP privada** del servidor, que no cambia al detener y prender las instancias |
| Telemetría | Linux Audit (`auditd`), llamadas `execve` de mi usuario, leídas por el agente desde `/var/log/audit/audit.log` |
| Control de costos | AWS Budget con alerta por email, creado antes de lanzar nada |

#### Decisiones de red (security group)

- SSH (22) y HTTPS (443): solo desde el bloque `/24` de mi proveedor. Mi IP pública cambió entre tres direcciones distintas del mismo bloque en menos de dos horas, y una `/32` me dejaba afuera cada rato. Es un compromiso consciente: menos estricto que `/32`, mucho más cerrado que `0.0.0.0/0`.
- 1514-1515 (agentes): solo desde el propio security group.
- Nunca `0.0.0.0/0`.

### Reglas

Todas cuelgan de la regla de fábrica **80792** ("Audit: Command") de Wazuh, que clasifica cualquier comando bajo la clave `audit-wazuh-c`. Esa regla base no tiene mapeo a MITRE y no distingue un `ls` inocente de algo sospechoso, así que las reglas propias agregan ese contexto.

| ID | Nivel | Qué detecta | ATT&CK |
| --- | --- | --- | --- |
| 100100 | 8 | `whoami`, `id`, `w`, `who` (descubrimiento de usuario) | T1033 |
| 100101 | 10 | `cp`, `mv` o `ln` sobre esos binarios (preparar una copia para renombrarla) | T1036.003 |
| 100102 | 7 | Cualquier binario ejecutado desde `/tmp`, `/var/tmp` o `/dev/shm` | T1036.003 |

Archivo completo: [`rules/local_rules.xml`](rules/local_rules.xml). El XML de las tres reglas está desplegable en la sección en inglés.

#### Decisiones de diseño

- IDs propios en el rango 100000-119999, para no chocar nunca con las reglas de fábrica.
- Nivel 8 para la 100100, no 12: un `whoami` aislado es un indicio, no una prueba de compromiso.
- `auid` y no `uid` en la regla de auditd: `auid` es el usuario de la sesión y se mantiene con `sudo`, así que escalar privilegios no esconde el comando.
- Flujo antes de cada cambio: backup de `local_rules.xml`, validación con `/var/ossec/bin/wazuh-analysisd -t` y recién después reinicio del manager.

### Resultados de validación

| Prueba | Resultado |
| --- | --- |
| `whoami`, `id` | Dispara la 100100 |
| `ls`, `date` | No dispara. Control: la regla base 80792 sí disparó, o sea que los eventos llegaron al servidor |
| `who`, `w` | Dispara la 100100 (tras ampliar la regla, ver Hallazgos) |
| `cp /usr/bin/id /tmp/idc` | Dispara la 100101 |
| `cp /etc/hostname /tmp/h` | No dispara (prueba negativa) |
| `cp /usr/bin/whoami /tmp/wm`, y después `/tmp/wm` | **No** dispara la 100100 (evasión). Dispara la 100102 |

Un resultado negativo solo vale si un control prueba que el evento llegó. Cada "no dispara" de arriba se contrastó con la regla 80792.

### Hallazgos

1. **Hueco de cobertura en mi primera versión.** La 100100 v1 cubría solo `whoami` e `id`. La página oficial de T1033 también lista `w` y `who` en Linux. La v2 los incluye.
2. **Renombrar rompe una regla basada en el nombre.** En la alerta de `/tmp/wm`, `audit.command` es `wm` y `audit.exe` es `/tmp/wm`. Un filtro por nombre de comando no ve la copia renombrada; la ruta sí. Eso es lo que usa la 100102.
3. **Wazuh y ATT&CK no coinciden en los nombres del mismo ID.**

   | | Wazuh 4.14.8 (alerta) | ATT&CK (página oficial, v19) |
   | --- | --- | --- |
   | Nombre de T1036.003 | Rename System Utilities | Rename Legitimate Utilities |
   | Táctica | Defense Evasion | Stealth (TA0005) |

   El ID coincide, así que el mapeo es correcto. Mi hipótesis, **sin verificar**, es que Wazuh trae un dataset de ATT&CK más viejo. Regla práctica: mapear por ID, nunca por nombre, y contrastar con la fuente primaria.

### Límites conocidos

- La 100100 marca `id` todas las veces, y scripts y administradores lo corren todo el tiempo. En un entorno real hace ruido.
- La 100101 detecta el paso previo (la copia), no el uso del binario renombrado.
- La 100102 tiene falsos positivos (instaladores, `snap`, scripts legítimos) y se evade ejecutando desde otra carpeta.
- Ninguna regla usa todavía `tty` ni `ppid` para separar uso interactivo de scripting.
- Probado en un solo endpoint, solo con mis propios comandos. No medí la tasa de falsos positivos.

### Hipótesis todavía sin probar

| Maniobra | Regla que debería verla | Estado |
| --- | --- | --- |
| Copiar a `/home/ubuntu` y ejecutar desde ahí | Solo la 100101 (la copia) | Hipótesis |
| `cd /usr/bin; cp whoami /tmp/x` (ruta relativa) | La 100101 probablemente no (el regex espera `/usr/bin/...`); la 100102 sí al ejecutarlo desde `/tmp` | Hipótesis |
| `cat /usr/bin/whoami > /tmp/x` y después `chmod +x` | La 100101 no; la 100102 sí al ejecutarlo desde `/tmp` | Hipótesis |
| Lo mismo, pero ejecutándolo desde `/home/ubuntu` | Ninguna (evasión completa) | Hipótesis |
| Script legítimo con `#!` ejecutado desde `/tmp` | La 100102 (falso positivo). Ver qué `exe` registra auditd | A medir |
| `echo $USER` | Probablemente nada (comando interno de la shell, sin `execve`) | Hipótesis |

### Cómo reproducirlo

1. **AWS.** Crear primero una alerta de presupuesto. Lanzar la AMI estándar **Ubuntu Server 24.04 LTS** de Canonical (evitar las variantes con SQL Server, Ubuntu Pro o Deep Learning, que suman costo o software que no hace falta). Poner las dos instancias en un mismo security group con las reglas de arriba.
2. **Servidor.** Quickstart oficial (all-in-one):
   ```bash
   curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
   ```
   Guardar en un lugar seguro la contraseña de admin que genera. Si `apt` da errores 404 en una instancia recién creada, correr antes `sudo apt update`.
3. **Agente del endpoint.** Usar el asistente "Deploy new agent" del dashboard (Linux, DEB amd64) con la **IP privada** del servidor.
4. **auditd en el endpoint.**
   ```bash
   sudo apt update && sudo apt -y install auditd
   sudo systemctl enable --now auditd
   sudo tee /etc/audit/rules.d/wazuh-cmds.rules > /dev/null <<'EOF'
   -a always,exit -F arch=b32 -S execve -F auid=1000 -F auid!=-1 -k audit-wazuh-c
   -a always,exit -F arch=b64 -S execve -F auid=1000 -F auid!=-1 -k audit-wazuh-c
   EOF
   sudo augenrules --load
   sudo auditctl -l
   ```
   Verificar antes tu UID con `id` (las reglas asumen 1000).
5. **Decirle al agente que lea el log de auditoría.** Si `grep audit /var/ossec/etc/ossec.conf` no devuelve nada, agregar este bloque junto a los otros `<localfile>` y reiniciar el agente:
   ```xml
   <localfile>
     <log_format>audit</log_format>
     <location>/var/log/audit/audit.log</location>
   </localfile>
   ```
6. **Reglas en el servidor.** Agregar las reglas al final de `/var/ossec/etc/rules/local_rules.xml`, y después `sudo /var/ossec/bin/wazuh-analysisd -t` y `sudo systemctl restart wazuh-manager`.
7. **Probar** en el endpoint y buscar `rule.id:(100100 or 100101 or 100102)` en Threat Hunting.

### Notas de troubleshooting

- **SSH `Connection timed out`:** el security group no coincidía con mi IP pública actual. Mi proveedor rota direcciones, así que abrí el `/24` del proveedor solo para SSH y HTTPS.
- **`UNPROTECTED PRIVATE KEY FILE` en Windows:** se resolvió con `icacls ... /inheritance:r` y `/grant:r`, dejando lectura solo para mi usuario.
- **`apt` con 404 en una instancia nueva:** índice de paquetes viejo. `sudo apt update` lo arregló.
- **Un archivo de reglas editado a mano en nano quedó dañado:** descarté los cambios sin guardar y, desde entonces, hago backups antes de editar.

### Control de costos

Detener las dos instancias después de cada sesión (una instancia detenida no cobra cómputo, pero el disco sigue cobrando), vigilar la alerta del presupuesto y borrar instancias y volúmenes al terminar el proyecto.

### Higiene de seguridad

- La clave `.pem` no va nunca a un repositorio (el `.gitignore` cubre `*.pem`).
- Ni contraseñas, ni IDs de cuenta, ni IPs públicas en este repo.
- Backup antes de editar archivos de reglas y validación antes de reiniciar.

### Cómo trabajé

Usé un asistente de IA como guía mientras armaba esto y traté su salida como una afirmación a verificar. Donde importaba, contrasté con la fuente primaria (documentación de Wazuh, attack.mitre.org). Esa verificación fue la que mostró la falta de cobertura de `w` y `who` y la diferencia de nombres de arriba.

### Hoja de ruta

- [x] Servidor Wazuh y endpoint Linux con telemetría de auditd
- [x] Tres reglas propias con pruebas positiva, negativa y de evasión
- [ ] Ejecutar las hipótesis sin probar y documentar los resultados
- [ ] Elegir un grupo de amenaza relevante para Linux y extraer técnicas de reportes públicos
- [ ] 8 a 10 técnicas, 10 a 12 reglas, cada una con prueba positiva, prueba de falsos positivos y nota de evasión
- [ ] Matriz de cobertura en ATT&CK Navigator
- [ ] Convertir 2 o 3 reglas a formato Sigma
- [ ] Endpoint Windows con Sysmon (fase 2)
- [ ] Ficha por regla, en inglés

### Evidencia

Las capturas están en [`evidence/`](evidence/):
`100100-whoami.png`, `100101-cp.png`, `100102-tmp-wm.png`, `control-80792-wm.png`.

### Fuentes

- [Quickstart de Wazuh](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh: Monitoring system calls, configuración](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html)
- [Wazuh PoC: Monitoring execution of malicious commands](https://documentation.wazuh.com/current/proof-of-concept-guide/audit-commands-run-by-user.html) (el enfoque con auditd está adaptado de acá)
- [MITRE ATT&CK T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [MITRE ATT&CK T1036.003: Rename Legitimate Utilities](https://attack.mitre.org/techniques/T1036/003/)

### Licencia

MIT.
