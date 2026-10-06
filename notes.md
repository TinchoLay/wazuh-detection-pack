# Wazuh Detection Pack: notas de laboratorio

Fecha de la sesión: 2026-10-06
Estado: lab armado y 3 reglas propias con evidencia. Falta elegir grupo de amenaza.

> Todo esto es trabajo personal de laboratorio, no producción.

## 1. Arquitectura del lab

| Componente | Detalle |
|---|---|
| Nube | AWS, región us-east-1 (N. Virginia), crédito de la cuenta |
| Servidor | Ubuntu Server 24.04 LTS, t3.xlarge (4 vCPU, 16 GB), 50 GiB gp3 |
| Wazuh | 4.14.8 all-in-one (manager, indexer, dashboard), instalado con el asistente oficial (`wazuh-install.sh -a`) |
| Endpoint | Ubuntu Server 24.04 LTS, agente Wazuh 4.14.8, nombre `endpoint-linux-01`. Tipo de instancia: t3.small según el plan (confirmar el tipo real) |
| Conexión agente-servidor | Por IP privada del servidor (no cambia al apagar y prender) |
| Presupuesto | AWS Budget de 10 USD con alerta por email |

### Decisiones de seguridad de red (security group `wazuh-sg`)
- SSH (22) y HTTPS (443): solo desde el bloque `/24` de mi proveedor. Mi IP pública rotó entre varias direcciones del mismo bloque en menos de dos horas, así que una IP puntual no funcionaba. Trade-off consciente: menos estricto que `/32`, pero mucho más cerrado que `0.0.0.0/0`.
- 1514-1515 (agentes): solo desde el propio security group.
- Nunca `0.0.0.0/0`.

## 2. Configuración del endpoint

### Reglas de auditd
Archivo: `/etc/audit/rules.d/wazuh-cmds.rules`

```
-a always,exit -F arch=b32 -S execve -F auid=1000 -F auid!=-1 -k audit-wazuh-c
-a always,exit -F arch=b64 -S execve -F auid=1000 -F auid!=-1 -k audit-wazuh-c
```

Carga: `sudo augenrules --load`. Verificación: `sudo auditctl -l`.

Diferencias respecto de la guía oficial de Wazuh (Proof of Concept, "Monitoring execution of malicious commands"):
- Se quitó `-F egid!=994`: es un grupo puntual de la máquina de ejemplo de la guía.
- Las reglas van en `/etc/audit/rules.d/` y no en `/etc/audit/audit.rules`, porque ese archivo se regenera desde la carpeta (criterio propio, a verificar).
- Se filtra por `auid` (usuario de la sesión original) y no por `uid`, para no perder comandos ejecutados con `sudo`.

La clave `audit-wazuh-c` ya viene mapeada como "command" en la lista `/var/ossec/etc/lists/audit-keys` del servidor.

### Bloque del agente (`/var/ossec/etc/ossec.conf`)
El agente se instaló antes que auditd, por eso hubo que agregarlo a mano.

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

## 3. Reglas propias (servidor, `/var/ossec/etc/rules/local_rules.xml`)

| ID | Nivel | Qué detecta | Técnica | Regla base |
|---|---|---|---|---|
| 100100 | 8 | `whoami`, `id`, `w`, `who` | T1033 | 80792 |
| 100101 | 10 | `cp`, `mv` o `ln` sobre esos binarios (staging para renombrar) | T1036.003 | 80792 |
| 100102 | 7 | Ejecución de un binario desde `/tmp`, `/var/tmp` o `/dev/shm` | T1036.003 | 80792 |

Archivo completo en `rules/local_rules.xml`.

Proceso seguido: backup del archivo, validación con `wazuh-analysisd -t` y recién después reinicio del manager.

## 4. Pruebas realizadas

| Prueba | Resultado |
|---|---|
| `whoami`, `id` | Dispara 100100 |
| `ls`, `date` | No dispara (el control confirmó que el evento llegó, regla 80792) |
| `who`, `w` | Dispara 100100 (después de ampliar la regla) |
| `cp /usr/bin/id /tmp/idc` | Dispara 100101 |
| `cp /etc/hostname /tmp/h` | No dispara (prueba negativa) |
| `cp /usr/bin/whoami /tmp/wm` y `/tmp/wm` | No dispara 100100 (evasión). Sí dispara 100102 |

Evidencia: carpeta `evidence/`.

## 5. Hallazgos

1. **Hueco de cobertura.** La v1 de la regla 100100 cubría solo `whoami` e `id`. La página oficial de T1033 menciona también `w` y `who` en Linux. La v2 los incluye.
2. **Evasión por renombre.** `audit.command` toma el nombre del proceso. Renombrar el binario esquiva un filtro por nombre. La ruta (`audit.exe`) sí delata la copia en `/tmp`.
3. **Discrepancia entre Wazuh y ATT&CK** para el mismo ID:

   | | Wazuh 4.14.8 | ATT&CK oficial (v19) |
   |---|---|---|
   | T1036.003 | "Rename System Utilities" | "Rename Legitimate Utilities" |
   | Táctica | Defense Evasion | Stealth (TA0005) |

   El ID coincide. Hipótesis (no verificada): Wazuh trae embebido un dataset de ATT&CK más viejo. Conclusión práctica: mapear siempre por ID y contrastar con la fuente primaria.
   Pendiente: revisar `attack.mitre.org/tactics/TA0005` y anotar qué dice sobre el cambio de nombre de la táctica.

## 6. Hipótesis a probar (todavía no probadas)

| Maniobra | Qué regla debería verla | Estado |
|---|---|---|
| Copiar a `/home/ubuntu` y ejecutar desde ahí | Solo 100101 (por la copia) | Hipótesis |
| `cd /usr/bin; cp whoami /tmp/x` (ruta relativa) | 100101 probablemente no (el regex pide `/usr/bin/...`); 100102 sí al ejecutarlo | Hipótesis |
| `cat /usr/bin/whoami > /tmp/x` y `chmod +x` | 100101 no; 100102 sí al ejecutarlo | Hipótesis |
| Lo mismo, ejecutando desde `/home/ubuntu` | Ninguna (evasión completa) | Hipótesis |
| Script legítimo con `#!` ejecutado desde `/tmp` | 100102 (falso positivo). Ver qué `exe` registra auditd | A medir |
| `echo $USER` | Probablemente nada (comando interno de la shell, sin `execve`) | Hipótesis |

## 7. Límites conocidos (para el README final)

- 100100 marca siempre `id`, que usan scripts y administradores todo el tiempo: ruido real en un entorno productivo.
- 100101 detecta el staging, no el uso del binario renombrado.
- 100102 tiene falsos positivos (instaladores, `snap`, scripts) y se evade ejecutando desde otra carpeta.
- Ninguna regla usa todavía `tty` ni `ppid` para distinguir contexto interactivo de scripting.

## 8. Pendientes

- Completar la tabla de hipótesis y documentar los resultados.
- Responder: ¿qué pasaría si la regla de auditd usara `uid=1000` en vez de `auid=1000`?
- Elegir grupo de amenaza (técnicas observables en Linux con auditd) y sacar técnicas de reportes públicos.
- Armar la ficha por regla del README: técnica, log source, campos, prueba, falsos positivos, evasión.
- Matriz de cobertura en ATT&CK Navigator.
- Convertir 2 o 3 reglas a formato Sigma.
- Windows con Sysmon en una fase 2.

## 9. Para retomar el lab

1. En EC2, prender servidor y endpoint. Las IP públicas cambian; las privadas no.
2. Si cambió el bloque de IP del proveedor, actualizar las reglas de SSH y HTTPS del security group.
3. En el servidor: `sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager`.
4. En el dashboard, confirmar que `endpoint-linux-01` figura Active.
5. Al terminar, detener las dos instancias. El disco sigue cobrando aunque estén apagadas. Al cerrar el proyecto: Terminate y borrar volúmenes e IPs sueltas.

## 10. Reglas de higiene

- La clave `.pem` no se sube nunca a un repositorio (`.gitignore` con `*.pem`).
- No pegar contraseñas ni claves en chats.
- Backup del archivo de reglas antes de editar y `wazuh-analysisd -t` antes de reiniciar.

## 11. Fuentes consultadas

- Wazuh Quickstart: https://documentation.wazuh.com/current/quickstart.html
- Wazuh, Monitoring system calls (configuración): https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html
- Wazuh PoC, Monitoring execution of malicious commands: https://documentation.wazuh.com/current/proof-of-concept-guide/audit-commands-run-by-user.html
- MITRE ATT&CK T1033: https://attack.mitre.org/techniques/T1033/
- MITRE ATT&CK T1036.003: https://attack.mitre.org/techniques/T1036/003/
