# Hallazgos de la fase 2 (notas de trabajo, 7 oct 2026)

Notas mías para armar el README. Cada punto tiene el test que lo respalda. Lo que no está verificado lo marco como tal.

## Reglas hermanas: qué gana cuando coinciden dos
- Hipótesis inicial: gana la primera del archivo. **Refutada.**
- Caso 1: `/tmp/masscan` coincidió con 100102 (nivel 7, más arriba) y 100140 (nivel 8, más abajo). Salió 100140.
- Caso 2: `/tmp/curl` coincidió con 100102 (nivel 7, más arriba) y 100110 (nivel 4, más abajo). Salió 100102.
- Los dos casos son compatibles con "gana el nivel más alto" y con nada más de lo que probé. No leí el código del motor.
- Sin probar: qué pasa con un empate de nivel. Mejor no depender de eso.

## Ruleset base que se come eventos
- La regla 92600 de Wazuh (nivel 0, `audit.exe` contiene "python") deja mudas todas las ejecuciones de Python.
- Efecto: mi cadena `curl|wget` -> IMDS no veía el acceso desde Python. Lo cerré con 100130/100131/100132 colgando de 92600.
- Cómo lo encontré: auditd tenía el evento, el dashboard no. Experimento 2x2 (Python sin paréntesis, paréntesis sin Python) y después `grep` al ruleset.

## Otros
- El timestamp de la alerta es cuando el servidor procesó el evento, no cuando se ejecutó el comando (retraso de 20 a 30 s).
- Cada login por SSH corre `who`, `id`, `id` como root sin terminal. Hace ruido en 100100; 100103 lo baja a nivel 3.
- Evasiones cerradas: T1105 (ruta relativa con cwd, opción pegada), IMDS (IP en decimal, hex y octal).
- Evasiones que quedan: IMDS en forma mixta (`169.16689662`), clientes que no son curl/wget/python, binarios renombrados (`scanner`).
- Sin verificar: si el agente decodifica los argumentos que auditd pasa a hex (los que llevan espacios). Las reglas de Python llevan las dos variantes por las dudas.

## Un comando, muchos eventos (técnicas 4 a 6)
- `useradd` suelto: 7 alertas en 100153. Árbol de procesos (`pid`, `ppid`): un proceso con 6 hijos que auditd también registra como `useradd`.
- `ausearch -p <pid> -i` mostró qué eran: `execve` fallidos (`success=no`, `exit=ENOENT`) de `/usr/sbin/sss_cache`, que no está instalado. Los intentos fallidos igual se registran con el nombre del padre.
- v2 de 100153: `regex success=yes` sobre el texto crudo (no verifiqué el nombre del campo decodificado). Resultado: `useradd` 1 alerta, `adduser` 2 (el propio `adduser` y el `useradd` real).
- Costo: un intento fallido de ejecutar una herramienta ya no alerta en esa regla. Solo la apliqué a 100153.
- `ufw disable` v1: unas 100 alertas de 100150 y 65 de 100151 (nivel 10), casi todas llamadas de iptables de ufw. El filtro `success` no ayudaría (no son fallos).
- `ufw` es un script de Python: su evento llega como 100130 (nivel 3), no como 100150. Regla 100133 (hija de 100130): `ufw disable` o `ufw reset` = una alerta de nivel 10.
- `ignore="60"` en 100151: de 65 alertas a 1. Los 63 `-F` suprimidos aparecieron como 100150 (nivel 5): bajan de nivel, no se descartan (visto en los datos, no leí el motor).
- Total de 100150 para un `ufw disable`: 162, mismo ppid, unos 40 ms (el timestamp es la hora de procesamiento del servidor).
- Costo de `ignore`: es por regla, no por host ni proceso; un `iptables -F` real en la ventana de 60 s sale en nivel 5 en vez de 10. No verifiqué `ignore` en la documentación.
- Decisión: no tocar 100150 (nivel 5 como contexto; la alerta accionable es 100133).
- Evasión confirmada: `iptables -P INPUT ACCEPT` solo llega a 100150 (nivel 5).
- T1686 (v19) vs T1562.004: corrí el `sed` a T1562.004 y `-t` aceptó ese ID. No confirmé que `-t` rechace T1686.

## authorized_keys y el watch que se queda ciego (técnica 7)
- `echo >>` es builtin de bash: el evento sale con comm=bash, sin proceso echo. Las reglas por comando no lo ven; hace falta watch de archivo (`-w ... -p wa -k audit-wazuh-w`).
- Cadena de fábrica: 80700 > 80780 (lista audit-keys, check_value write) > 80781/80782 (nombre de archivo o de directorio) > 80790/80791 (if_group audit_watch_write, match `type=CREATE`/`type=DELETE`, que también calza con `nametype=...`).
- Reglas: 100160 (escritura en authorized_keys, hija de 80780, regex sobre el texto crudo), 100161 (directorio .ssh movido o borrado), 100162 (op=remove_rule con clave audit-wazuh-*, hija de 80705).
- Predicciones falladas: `sed -i` escapa al watch (no, rename con la clave); el mv sin alerta en Wazuh (no, salía 80705 y mi filtro por clave la escondía porque Wazuh decodifica la clave como null); el watch por directorio sobrevive y sigue al directorio nuevo (no, queda pegado al inodo viejo); la alerta del sed era 80782 (era 80791).
- Inodos: .ssh.old2 = 295508 (el armado a las 19:14), .ssh vivo = 295521. Escribir en old2 se registra, en el nuevo no.
- `audit.file.name` decodificado = primer PATH (el directorio padre). Por eso las reglas comparan texto crudo. `wazuh-logtest` lo mostró.
- Un `sed -i` con watch por directorio da 4 alertas (80790 temporal, 80781 fchown y fsetxattr, y 100160). Una sola de nivel 10.
- /root/.ssh: probado con sudo (auid sigue en 1000). `wc -c` volvió a 255 después de limpiar.
- Demora auditd a Wazuh: menos de 2 s en estas pruebas (antes medí 20 a 30 s). No es constante.
- Pendiente: persistir los watches en /etc/audit/rules.d/wazuh-files.rules (augenrules --load recarga todo; -D de audit.rules generaría ráfaga de 100162), `auditctl -e 0` sin probar, FIM como segunda capa.
- Persistencia hecha: /etc/audit/rules.d/wazuh-files.rules. `augenrules --load` empieza con -D: 4 alertas 100162 (una por regla quitada, incluidas las de execve) y varias 80705 en unos 40 ms. Es lo que se vería con `auditctl -D`.
- `auditctl -e 0`: solo 80705 (nivel 3). En el log de audit queda `op=set audit_enabled=0 old=1`; el `-e 1` siguiente NO queda registrado. Regla 100163 (hija de 80705, nivel 12). Control: `-e 1` con la auditoría ya encendida da solo 80705. La decodificación de CONFIG_CHANGE no trae auid, por eso la descripción no lo usa.
- Control real: modo inmutable (`-e 2`). No activado en el lab (cada cambio de reglas pediría reinicio).
- Reinicio de la instancia para verificar que los watches vuelven: sin probar.

## Servicios de systemd (técnica 8)
- Reglas: 100170 (archivo de unidad creado o borrado directo en /etc/systemd/system, hija de 80780, nivel 10) y 100171 (systemctl enable|reenable|link, hija de 80792, nivel 6).
- Predicciones cumplidas: tee de la unidad = 100170; daemon-reload y enable = solo 80792; el symlink de wants/ no se registra (ausearch: 0 líneas); la unidad de usuario en ~/.config/systemd/user escapa a todo.
- ausearch -c 'multi-user.target.wants' = 0: los watches de directorio no son recursivos (conclusión mía, no verificada en documentación).
- v2: 100171 atrapa `sudo systemctl enable` y `systemctl --user enable` (segunda ejecución). Control `is-enabled` = solo 80792. `disable` no dispara.
- `sudo rm` de la unidad = 100170 (la regla compara nombre, no distingue crear de borrar). Descripción dice "written": pendiente cambiar en el servidor a "written or deleted" junto con el próximo reinicio del manager.
- Cada `systemctl --user` registra helpers de systemd (30-systemd-environment-d-generator, systemd-xdg-autostart-generator) como 80792 nivel 3.
- ossec.log del agente: 5 "Lost connection with manager" (18:59, 19:26, 19:39, 19:42, 19:46 UTC), que coinciden con mis reinicios del manager. Quizás explican la demora de 20-30 s de pruebas anteriores (suposición). Esperar ~30 s después de reiniciar.
- Evento perdido sin explicar: `systemctl --user enable` de 19:46:47 (evento audit 2151) no llegó a Wazuh aunque los de antes y después sí y el agente ya había reconectado. Repetido, alertó.
- Persistencia: tercer watch en /etc/audit/rules.d/wazuh-files.rules; augenrules --load dio 5 alertas 100162 (una por regla quitada).
- Sin probar: ln -s a mano, systemd-run, /usr/lib/systemd/system, /run/systemd/system, falsos positivos con apt.

## /etc/ld.so.preload (técnica 9, T1574.006)
- Regla: 100180 (nivel 12, hija de 80780, regex name="/etc/ld\.so\.preload"). El archivo no existe en Ubuntu 24.04 limpio.
- Predicciones cumplidas: auditd acepta -w sobre archivo inexistente (salida 0); crear alerta; el watch sobrevive a rm + recreación; mv encima también se ve. No predije que el stock ya alertaba (80790/80781/80791 en nivel 3, con el nombre del archivo en la descripción).
- Antes de la regla: touch = 80790, `: >` = 80781 (truncar no logra CREATE ni DELETE), rm = 80791. Con la regla: 5 eventos, 5 alertas 100180, sin stock al lado (gana el nivel más alto).
- mv de /tmp/lsp: 3 PATH con el nombre (CREATE del nuevo, DELETE del viejo, DELETE del temporal). sed -i: arma el temporal /etc/sedXXXXXX y lo renombra. El archivo post-mv quedó ubuntu:ubuntu 664 (mv conserva dueño).
- Inode 2986 reutilizado (era el de testtnt.service borrado minutos antes).
- Control negativo: touch/rm de ld.so.preload.bak no genera nada.
- Persistencia: cuarto watch en rules.d/wazuh-files.rules; tras `reboot`, auditctl -l mostró los 2 execve + 4 watches, auditd y wazuh-agent activos. Esto cierra el pendiente de la prueba de reinicio (probado para los 4 watches y los execve, no para otras cosas).
- Cambié la descripción de 100170 a "written or deleted" en la copia local y en el servidor (confirmado en el server con grep -c = 1).
- Sin probar: LD_PRELOAD por variable de entorno, /etc/ld.so.conf.d + ldconfig, falsos positivos en otros sistemas.

## Borrado de logs (técnica 10, T1070.002 / T1070.004)
- Reglas: 100190 (DELETE/rename de archivo directo en /var/log, auid real, ignore=60), 100191 (openat con O_TRUNC, bit 0x200 de a2), 100192 (truncate/shred con ruta /var/log/ en argumentos, hija de 80792). Watch: -w /var/log -p wa -k audit-wazuh-w (persistido en wazuh-files.rules).
- Predicciones falladas: (1) creí que el watch de directorio no veía truncar ni append: registra cada apertura para escritura de hijos directos; (2) creí que sshd tendría auid unset: trae el auid del usuario; (3) creí que O_TRUNC identificaba el truncado: truncate -s 0 abre con a2=841 (sin O_TRUNC) y vacía con ftruncate, que el watch no registra.
- Línea base de ruido (ventana 20:27:10): 159 logrotate, 14 apt-get, 4 dpkg, 3 sshd, 1 landscape-sysinfo con auid ubuntu; rsyslogd (2) y sysstat/sadc (1) con auid unset. Por syscall: 99 rename + 4 unlink + 19 fchmod + 11 fchown + 11 fsetxattr + 15 openat (logrotate), 2 unlink + 4 chmod + 2 chown + 6 openat (apt-get), openat sin nada destructivo en dpkg y sshd.
- Mi primer test mezclo todo dentro de 20 s y el ignore=60 silencio rm y logrotate (solo alerto mv). Repetido con pausas de 65 s: rm = 100190, logrotate -f = una alerta 100190, apt = nada.
- Raw: a2 en hex sin 0x (a2=841); la línea trae campos enriquecidos al final (SYSCALL=openat AUID="ubuntu"). Mi grep de 0x241 se encontro a sí mismo (auditd registra los args del grep).
- DUDA ABIERTA: el watch -w /var/log registró eventos de /var/log/apt/ (subdirectorio), lo que contradice el hallazgo 12 (no recursivo). Kernel tras el reboot: 7.0.0-1013-aws (no anoté el anterior). Falta: uname -r, ls /boot/vmlinuz-*, y probar mkdir /var/log/testtnt.d + touch dentro + ausearch. Si se confirma, reescribir hallazgos 8 y 12 (y la pregunta de si los tests anteriores a las 20:16 UTC valen en este kernel).
- Sin probar: systemd-run rm (auid unset, evasión predicha), borrado en /var/log/audit y /var/log/journal, shell history (history -c, unset HISTFILE, rm ~/.bash_history; T1070.003), falsos positivos en otros sistemas.

## PID 1 y audit=1 (hallazgo 12 corregido)
- Mi afirmación "un watch de directorio no ve adentro de subdirectorios" estaba MAL. Archivo regular creado en /var/log/testtnt.d/ (touch) y en /etc/systemd/system/testtnt.d/ (touch a.conf): visto. Symlink directo en /etc/systemd/system (ln -s): visto. Symlink con ln -s dentro de multi-user.target.wants/: visto. Solo el symlink de `systemctl enable` no se veia.
- Hipótesis del kernel cambiado con el reinicio: FALSA. Arranques: 6.17.0-1017-aws el 06/10 17:47 UTC y el 07/10 13:26 UTC; 7.0.0-1013-aws desde el arranque de las 18:03 UTC (y el de las 20:16 UTC). Las pruebas de authorized_keys y systemd (19:xx UTC) ya corrieron con el 7.0.
- Causa: `systemctl enable` lo ejecuta PID 1 por D-Bus. /proc/cmdline sin audit=1: no se ve. `systemctl --root=/ enable` (lo hace el propio proceso systemctl): se ve (evento 2118, comm systemctl). Con audit=1 + reboot: `systemctl enable` normal se ve, evento 499 con proctitle=/sbin/init, mode=link, CREATE, a las 20:53:20 UTC. Mecanismo del kernel (procesos previos a auditd sin contexto de auditoria) de memoria, no verificado en documentación.
- Dato raro sin explicar: el evento del symlink de systemctl registra como name la ruta de la unidad (/etc/systemd/system/testtnt.service) y no la de multi-user.target.wants/.
- Cambios: /etc/default/grub.d/99-audit.cfg (GRUB_CMDLINE_LINUX con audit=1) + update-grub; copia en auditd/99-audit.cfg. Tras el reinicio: cmdline con audit=1, 2 execve + 5 watches cargados (incluye /var/log persistido), auditd y wazuh-agent activos.
- Errores míos en esta tanda: predije que el kernel cambio con el reinicio (falso); predije que el symlink de enable se veria en el kernel nuevo (falso); mande pasos de limpieza que pisaron pruebas siguientes (testtnt.d ya no existia); mi primer grep de 0x241 se encontro a si mismo.
- Pendiente: medir el ruido extra con audit=1 (journald, otros demonios), repetir con audit=1 las pruebas anteriores que dependan de PID 1, historial de la shell (T1070.003: history -c, unset HISTFILE, rm ~/.bash_history), reglas de logs sobre subdirectorios (/var/log/audit, /var/log/journal), evasión con systemd-run confirmada (auid=unset, solo 80791 nivel 3).

## Historial de la shell (técnica 10, parte 2, T1070.003)
- Ronda 1 (shell anidada con HISTFILE=~/.testtnt_hist): control = uno, dos; `history -c` = el archivo conserva las líneas viejas (histappend en el .bashrc de Ubuntu), solo se pierde la sesión; `unset HISTFILE` y `kill -9 $$` = no se guarda; ninguno deja evento (builtins/señal). truncate/shred -u/ln -s/rm = solo 80792 nivel 3. Cada bash -i anidado dispara lesspipe, basename, dirname, dircolors (80792) por el .bashrc.
- Línea base de logout con watch: 2 eventos de bash, openat O_WRONLY|O_APPEND y chown, sin O_TRUNC ni DELETE. Archivo 19045 -> 19081 bytes.
- Reglas: 100200 (nametype=DELETE sobre .bash_history/.zsh_history/.sh_history de /home/* o /root), 100201 (openat con O_TRUNC), 100202 (comando rm|shred|truncate|ln|mv|unlink con nombre de historial en los args; cp excluido). Watches: /home/ubuntu/.bash_history y /root/.bash_history (en rules.d del endpoint falta persistirlos con augenrules --load).
- Resultados 16:12 local: `: >` = 100201; truncate -s 0 = 100202 solo; `history -w` = 100200 (predije 100201, FALLE; no miré el evento, suposición: bash escribe un temporal y renombra); mv ida y vuelta = 100202 + 100200 + 100202 (el segundo mv tiene el historial como destino); ln -sf = 100200 + 100202; rm = 100200 + 100202; shred -u = 100200 + 100202; cp de restauración = nada.
- Sin probar: cp /dev/null, dd, sed -i sobre el historial, HISTFILE=/tmp/x, .zsh_history, usuarios sin watch, HISTFILESIZE superado en el logout.
- Pendiente de limpieza en el endpoint: ~/.bash_history.bak, ~/.bash_history.bak2 (el nombre .bash_history.bakN no matchea 100202 porque la regex exige la comilla después de history).
- Mecanismo de `history -w` resuelto (ausearch 19:12:28 UTC, evento 742): rename de /home/ubuntu/.bash_history-02068.tmp sobre .bash_history (DELETE inode 295989, CREATE inode 295532, DELETE del tmp) + chown (evento 743). La suposición era correcta. El watch por nombre siguió vivo.
- Persistencia: 2 watches de historial agregados a rules.d; auditctl -l | grep -c audit-wazuh-w = 7 tras augenrules --load. Backups .bak y .bak2 borrados.
- A VERIFICAR: la salida de auditctl -s (via augenrules --load) mostro `lost 61` (antes del reinicio de ayer mostraba lost 0). Hipotesis: eventos perdidos en el arranque con audit=1 porque el backlog_limit del kernel es 64 hasta que auditctl lo sube a 8192 (parametro audit_backlog_limit=8192 en el kernel). No verificado: falta mirar `dmesg | grep -i audit` y ver si `lost` crece durante las pruebas.

## Eventos perdidos con audit=1 (hallazgo 21)
- Con solo audit=1: `auditctl -s` mostraba lost 61 (antes del reinicio sin audit=1 era 0). No crecio al forzar `logrotate -f` (unos 100 eventos): quedo en 61 antes y despues.
- journalctl -k -b: el kernel imprime registros de auditoria desde el segundo cero (audit: enabled, state=initialized), antes de auditd, y los primeros son de PID 1: type=1334 op=LOAD/UNLOAD + syscall=321 (bpf) de systemd. systemd-journald dice "Collecting audit messages is disabled". El dmesg ya no tenia esas lineas.
- Hipotesis: la cola del kernel es de 64 hasta que auditctl la sube a 8192 y la rafaga del arranque la desborda.
- Prueba: GRUB_CMDLINE_LINUX con audit=1 audit_backlog_limit=8192 + reboot: lost 0, backlog_limit 8192, 2 execve + 7 watches (9 reglas con audit-wazuh), auditd y wazuh-agent activos. Un arranque contra otro, sin contar los eventos del arranque: causa probable, no probada.
- Aplicado en /etc/default/grub.d/99-audit.cfg (copia en auditd/99-audit.cfg) y en la seccion de reproduccion del README.
- Error mio: pegue la linea de GRUB como si fuera un comando y la termine con una comilla de mas en la terminal; no paso nada.

