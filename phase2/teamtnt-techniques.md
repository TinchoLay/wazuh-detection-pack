# Fase 2: TeamTNT (G0139), tabla de técnicas

Fuentes: página de ATT&CK de TeamTNT (v19, modificada el 31 jul 2026) y el análisis de Unit 42 sobre Hildegard. Los datos salieron de lecturas resumidas de esas páginas, así que cada técnica se confirma en attack.mitre.org antes de escribir su regla. El informe de Trend Micro sobre credenciales de AWS no publica comandos ni rutas, por eso no se usa para eso.

## Cómo la ve mi lab

- **execve**: auditd registra el comando y sus argumentos (lo que ya tengo con `audit-wazuh-c`).
- **archivo**: hay que agregar reglas de vigilancia `-w` (nuevo en esta fase).
- **ciega**: no genera ni execve ni escritura de archivo, así que mi lab no la ve.

## Núcleo (10 reglas), de más simple a más difícil

| # | Técnica (ATT&CK) | Qué hace TeamTNT | Cómo la ve auditd | Dificultad | Qué enseña |
| --- | --- | --- | --- | --- | --- |
| 1 | T1105 Ingress Tool Transfer | `curl` y `wget` para bajar herramientas y scripts | execve (`curl`, `wget`) | Fácil | Un comando legítimo solo sirve combinado con contexto (destino en `/tmp`, salida a `sh`) |
| 2 | T1552.005 Cloud Instance Metadata API | Consulta el servicio de metadatos de AWS para robar credenciales (`169.254.169.254`) | execve con esa IP en los argumentos | Fácil | Detección propia de AWS, probada en tu EC2 real |
| 3 | T1219 Remote Access Tools y T1046 Network Service Discovery | `tmate` para acceso remoto, `masscan`, `zmap` y `zgrab` para escanear | execve por nombre de binario | Fácil | Los IOC por nombre son frágiles: ya viste que renombrar los rompe |
| 4 | T1686 Disable or Modify System Firewall | Desactiva `iptables` | execve (`iptables -F`, `ufw disable`) | Fácil | Un ID de ATT&CK v19 que Wazuh puede no conocer (ver nota abajo) |
| 5 | T1222.002 File and Directory Permissions Modification | `chattr` sobre binarios | execve (`chattr`) | Fácil | Ruido bajo, valor alto |
| 6 | T1136.001 Create Account: Local Account | Crea usuarios locales con privilegios | execve (`useradd`, `adduser`) | Fácil | Falsos positivos de administradores |
| 7 | T1098.004 SSH Authorized Keys | Agrega claves RSA a `authorized_keys` | archivo (vigilancia de `~/.ssh/authorized_keys`) | Media | Tu primera regla de archivo y sus claves de Wazuh |
| 8 | T1543.002 Systemd Service | Crea un servicio systemd para el minero | archivo (`/etc/systemd/system`) más execve (`systemctl enable`) | Media | Correlacionar dos tipos de evento |
| 9 | Dynamic Linker Hijacking (ID a verificar) | Modifica `/etc/ld.so.preload` para ocultar procesos (Hildegard) | archivo (vigilancia de `/etc/ld.so.preload`) | Media | Archivo que normalmente no existe: casi sin falsos positivos |
| 10 | T1685.006 Clear Linux or Mac System Logs y T1070.004 File Deletion | Borra `/var/log/syslog` y los scripts después de usarlos | execve (`rm`) más archivo (`/var/log`) | Media | Ver el borrado de un log desde otra fuente |

## Extras (si queda tiempo)

| # | Técnica | Nota |
| --- | --- | --- |
| 11 | T1059.009 Cloud API (AWS CLI) | auditd solo ve el comando local (`aws ...`). La detección real está en CloudTrail, que mi lab no cubre. Sirve para documentar un límite |
| 12 | T1613 Container and Resource Discovery (`docker ps`, `docker inspect`) | Pide instalar Docker, y los administradores lo usan todo el día |
| 13 | T1036.005 Masquerading | Hildegard disfraza un proceso como `bioset`. Conecta con la regla 100102 de la fase 1 |

## Lo que mi lab no ve (para el README)

- **T1070.003 Clear Command History (`history -c`)**: es un comando interno de la shell, sin `execve`. Alternativa: vigilar el archivo `.bash_history`, aunque el comando solo borra la memoria hasta salir de la sesión. Es la oportunidad de confirmar con una prueba mi hipótesis sobre `echo $USER`.
- **Procesos ocultos con `ld.so.preload`**: según Unit 42, `ps` y `top` no muestran el minero ni `tmate`. auditd registra el execve en el kernel, pero lo que se ve en la máquina engaña. Es un buen caso para explicar en una entrevista por qué conviene tener telemetría fuera del propio equipo.
- **Actividad de nube con credenciales robadas**: sucede en AWS, no en el endpoint.

## Nota sobre IDs de ATT&CK v19

La página de TeamTNT usa IDs nuevos para técnicas que antes tenían otro número (por ejemplo, T1686 y T1685.006). Wazuh 4.14.8 puede no reconocerlos. Antes de escribir cada regla: probar el ID con `wazuh-analysisd -t` y, si no lo acepta, usar el ID anterior y anotar la diferencia en el README. Es la misma discrepancia de la fase 1 (T1036.003), con más evidencia.
