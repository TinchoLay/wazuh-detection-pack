# Honeypot integration

**[English](#english) | [Español](#español)**

---

## English

Wazuh rules for the events written by the [ssh-honeypot](https://github.com/TinchoLay/ssh-honeypot) project. The honeypot runs in Docker on its own EC2 instance, with a Wazuh agent that reports to the same manager as the rest of this pack.

This is lab work, not production.

### How it fits together

```
attacker -> honeypot container -> logs/*.json (bind mount) -> Wazuh agent -> manager -> rules 100300 to 100347
```

Agent side, in `ossec.conf` of the honeypot instance:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/honeypot-aws/logs/*.json</location>
</localfile>
```

The honeypot writes one JSON object per line with a `honeypot_event` field: `ssh_login_attempt`, `http_request`, `ftp_login_attempt`, `shell_command` or `malware_capture`.

Manager side: copy the rule files to `/var/ossec/etc/rules/`, check them with `wazuh-analysisd -t` and restart the manager. Reloading is not enough, see the notes below.

### Files

| File | Rules |
|---|---|
| `honeypot_rules.xml` | 100300 to 100320: SSH, shell commands and malware captures |
| `honeypot_rules_http.xml` | 100340 to 100347: HTTP and FTP |
| `honeypot_ioc_rules.xml` | 100330: failed logins from a known attacker IP |
| `honeypot-attackers.example` | Format of the CDB list that rule 100330 reads |

The name `honeypot_rules_http.xml` is deliberate. Wazuh loads rule files in alphabetical order and a child rule has to load after its parent. My first name, `honeypot_http_rules.xml`, sorted before `honeypot_rules.xml`, so the HTTP rules were loaded before the rule they depend on (100300) and were ignored. More on that below.

### Rules

| ID | Level | What it detects |
|---|---|---|
| 100300 | 0 | Any honeypot event (parent rule) |
| 100301 | 2 | SSH login attempt. Below the default alert threshold (3), so it is counted but not shown |
| 100302 | 10 | 8 login attempts from the same IP in 60 s (T1110). `ignore="60"` limits repeats |
| 100303 | 8 | Slow brute force: 5 login attempts from the same IP in 10 minutes (T1110) |
| 100310 | 8 | Download attempt from the fake shell (T1105) |
| 100320 | 12 | Captured file flagged as malicious by at least one VirusTotal engine (T1105) |
| 100330 | 12 | Failed authentication on a real system from an IP in the honeypot attacker list (T1110) |
| 100340 | 2 | Any HTTP request (base rule for the HTTP set, counted but not shown) |
| 100341 | 8 | Request to `GponForm/diag_Form`, the GPON router exploit path (T1190) |
| 100342 | 5 | Open proxy probe: a full URL as the path, or `CONNECT host:port` (T1595) |
| 100343 | 5 | WebLogic T3 handshake sent to the HTTP port (T1595.002) |
| 100344 | 3 | Traffic that is not HTTP at all, such as a stray protocol or binary junk (T1595) |
| 100345 | 5 | Probe for a known target: `wp-json`, `wp-login`, `xmlrpc.php`, `/.env`, `/.git`, `phpmyadmin`, `actuator`, `/solr`, `manager/html`, Jenkins, GeoServer (T1595.002) |
| 100346 | 5 | 10 HTTP requests from the same IP in 120 s, `ignore="300"` (T1595) |
| 100347 | 4 | FTP login as `anonymous` (T1078) |

Severity follows how much evidence there is. A login attempt or a plain GET is noise, a request to an exploit path shows intent, and a sample that VirusTotal confirms is proof.

The HTTP honeypot also stores the POST body. That matters for 100341: the GPON exploit puts its command in the body, not in the URL, and the path alone does not say what the attacker wanted to run.

### Attacker IP list (CDB)

`honeypot-attackers.example` shows the format (`ip:label`). Install it as `/var/ossec/etc/lists/honeypot-attackers`, register `<list>etc/lists/honeypot-attackers</list>` in the `<ruleset>` block of `ossec.conf` and restart the manager. Rule 100330 raises a failed login from a listed IP from the stock level 5 (`5760`) to level 12.

Status: simulated only. I checked the lookup and the rule priority with `wazuh-logtest`: a listed IP gave 100330 and an unlisted one gave 5760. The list is filled by hand. Feeding it from alerts 100302 and 100320 would need a script and a manager restart to reload it. I have not built that.

### What I learned while testing

- **Rule files load in alphabetical order.** A child rule (`if_sid`) must come after its parent. With the wrong file name, `wazuh-logtest` printed warnings and the rules did nothing. Renaming the file fixed it.
- **The field name matters.** My first version used `event_type`, which collided with the stock Suricata rule 86600. Renaming it to `honeypot_event` fixed it.
- **Level 0 rules do not count toward frequency rules.** The base login rule is level 2 on purpose, so 100302 can count it. The same goes for 100340 and 100346.
- **`wazuh-logtest` is not production.** It reloads the rules on every run and the running engine only loads them at manager start. The rules passed in logtest and produced nothing live until I restarted the manager.
- **JSON strings stop at a null byte.** A request that began with a null character arrived with an empty `method`, because the decoder cuts the string at `\u0000`. That is why 100344 looks at what the method is not, instead of looking for known junk.
- **Wildcard paths find new files late.** The agent noticed a new file about 40 s after it appeared and only read what came after. That is an observation from two tests, not a measured interval.
- **Nested JSON fields use dots**, for example `virustotal.maliciosos`.
- **Frequency rules group by source IP, so the source IP has to be real.** Docker publishes ports through `docker-proxy`. A redirect to that proxy port makes every attacker look like the bridge address, and 100302, 100303 and 100346 would count all of them as one. For the SSH port I forward with DNAT straight to the container, which keeps the real source address.
- **Cleaning your own test traffic takes three places.** My own connections reached the honeypot logs, the Wazuh alert files and the indexer. My first cleanup did nothing, and I only noticed because I counted afterwards. After the second try the count was zero.

### Network isolation

The honeypot instance has its own security group. Inbound, the honeypot ports are open to the internet: 2222, 8080, 2121 and now 22 (see below). Outbound traffic is limited to what the project needs:

| Port | Destination | Why |
|---|---|---|
| TCP 1514, 1515 | Wazuh manager only (/32) | Agent events and enrollment |
| TCP 443 | Any | VirusTotal lookups and HTTPS sample downloads |
| TCP 80 | Any | HTTP sample downloads |

Checked from the instance: 80 and 443 answer, ports 22 and 25 to the internet time out, 1514 to the manager connects, the agent stays `Active` and the container still reaches VirusTotal.

Limits, stated plainly:
- 80 and 443 must stay open to any destination because the honeypot downloads whatever URL an attacker types. The security group cannot tell that apart from a legitimate request. The protection against internal targets lives in the code (`url_es_segura`), and it does not cover DNS rebinding.
- Downloads from other ports, such as 8080, time out by design. How the code reports that failure has not been tested.
- From the AWS documentation (not tested here): security groups do not filter traffic to the VPC DNS resolver, instance metadata or the time service. DNS therefore stays an exit path this control cannot close. Metadata access from the container is blocked separately (IMDSv2 with hop limit 1, no instance role).

### First night exposed

The honeypot ran with ports 2222 (fake SSH), 8080 (fake HTTP) and 2121 (fake FTP) open to the internet for about 15 hours. This is one small overnight sample, so it is a case study and not statistics.

What arrived:
- 27 HTTP requests from about nine sources, almost all plain GETs with no credentials. Several sources sent bursts of 3 to 6 requests within seconds, which points to scripts probing several paths.
- 3 SSH login attempts, all from one source, using `root` with `123456`, `password` and `12345678`.
- No malware downloads and no shell commands. Nobody got past the login, which is expected on a non-standard port.

What the HTTP probes were looking for:

| Path | What it tells |
|---|---|
| `/` (19 times) | "Is anything listening?" The first step of any scanner |
| `/wp-json`, `/license.txt` | Looking for WordPress and its version |
| `/hudson` | Looking for a Jenkins CI server |
| `/login`, `/favicon.ico` | Generic login panel search and product fingerprinting |
| `http://a7x[.]overflow[.]biz/hachk.php` | A full URL sent as the path: a test for an open proxy. The honeypot does not proxy, so nothing was fetched |

Two non-HTTP payloads also arrived (a lone Arabic character and a short text block with `AS:2048`). I could not identify the second one, so I am not guessing.

Nothing resembled exploitation. Everything was reconnaissance (ATT&CK T1595, active scanning).

The most useful finding was the SSH source. It sent one attempt about every 30 seconds. Rule 100302 needs a burst of attempts inside 60 seconds, so this pattern would never have triggered it. That is a low and slow brute force, and it exposed a gap in my own detection that I only found because I had real traffic.

I closed it with rule 100303 (5 attempts in 10 minutes, level 8). Tested two ways:
- In `wazuh-logtest`, 12 attempts in a row: 100303 fired on the 5th event and 100302 on the 9th. I read the 9th as the 8th counted login, because the 5th was consumed by 100303. That explanation is my interpretation, the position is the measurement. After each firing the next events fell back to 100301, which is consistent with `ignore` working.
- Live, 6 attempts 30 seconds apart: exactly one alert, 100303, and no 100302.

On a fast burst both rules fire, first level 8 and then level 10, so severity escalates by itself.

### The HTTP and FTP rules (100340 to 100347)

The first night showed what HTTP scanners send, but the first version of the pack only had SSH rules. I wrote the HTTP set after reading what had actually arrived: GPON exploit attempts, open proxy probes, a WebLogic handshake on an HTTP port and the usual hunt for WordPress and Jenkins.

How I checked them:
- Each of the eight rules in `wazuh-logtest`, with a sample event.
- Live, with real traffic that reached the honeypot and a burst test I generated myself.
- By design, a plain `GET /` stays at level 2, so it is counted for 100346 but does not reach the dashboard.

Limits:
- 100345 matches path fragments. A real application that has a `/solr` or `/.git` path would trigger it, and it is a list I wrote from what I saw, not a complete one.
- 100344 is level 3, the lowest that reaches the dashboard. I do not know yet whether it is more useful than noisy.
- 100347 treats any anonymous FTP login as suspicious. On a honeypot that is fair, on a real FTP server it would not be.

### Port 22

The fake SSH was listening only on 2222, which scanners rarely try first. I opened port 22 to the internet with a DNAT rule to the container, and the real admin `sshd` stays key-only behind it. The rule is not persistent: after a reboot the real `sshd` answers on 22 again, which is the safe direction to fail.

Status: just opened. I will add the results here once it has collected a day or two of traffic, including whether the SSH rules (100301, 100302, 100303) fire on real attackers from end to end.

### Verified and not verified

Verified end to end with synthetic events (documentation IPs `203.0.113.x`): 100310, 100320, 100302 and 100303 reach `alerts.json`, and 100301 does not (level 2, below the alert threshold of 3). Ten login attempts from one IP produced exactly one 100302 alert.

Verified in `wazuh-logtest` and live: the HTTP and FTP set, 100340 to 100347.

Verified after a stop and start of both instances: the honeypot container comes back on its own (`restart: unless-stopped`) and the agent reconnects to the manager.

Verified only in `wazuh-logtest`: 100330 and the CDB lookup (simulated, see above).

Not isolated: whether `ignore="60"` suppresses repeats. The test sent 10 attempts, which cannot reach a second burst of 8, so it does not tell `ignore` apart from the frequency counter alone.

Not verified: whether Filebeat sends duplicate alerts to the indexer after an alert file is shortened by hand, as I did when cleaning my own traffic. Also not measured yet: behavior under real SSH traffic on port 22.

---

## Español

Reglas de Wazuh para los eventos que escribe el proyecto [ssh-honeypot](https://github.com/TinchoLay/ssh-honeypot). El honeypot corre en Docker en su propia instancia EC2, con un agente de Wazuh que reporta al mismo manager que el resto de este pack.

Es trabajo de laboratorio, no de producción.

### Cómo encaja todo

```
atacante -> contenedor honeypot -> logs/*.json (bind mount) -> agente Wazuh -> manager -> reglas 100300 a 100347
```

Del lado del agente, en el `ossec.conf` de la instancia del honeypot:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/honeypot-aws/logs/*.json</location>
</localfile>
```

El honeypot escribe un objeto JSON por línea con un campo `honeypot_event`: `ssh_login_attempt`, `http_request`, `ftp_login_attempt`, `shell_command` o `malware_capture`.

Del lado del manager: copiar los archivos de reglas a `/var/ossec/etc/rules/`, validarlos con `wazuh-analysisd -t` y reiniciar el manager. Recargar no alcanza, mirá las notas más abajo.

### Archivos

| Archivo | Reglas |
|---|---|
| `honeypot_rules.xml` | 100300 a 100320: SSH, comandos de la shell y capturas de malware |
| `honeypot_rules_http.xml` | 100340 a 100347: HTTP y FTP |
| `honeypot_ioc_rules.xml` | 100330: logins fallidos desde una IP de atacante conocida |
| `honeypot-attackers.example` | Formato de la lista CDB que lee la regla 100330 |

El nombre `honeypot_rules_http.xml` es a propósito. Wazuh carga los archivos de reglas en orden alfabético y una regla hija tiene que cargarse después de su padre. Mi primer nombre, `honeypot_http_rules.xml`, quedaba antes que `honeypot_rules.xml`, así que las reglas HTTP se cargaban antes de la regla de la que dependen (100300) y se ignoraban. Más abajo está el detalle.

### Reglas

| ID | Nivel | Qué detecta |
|---|---|---|
| 100300 | 0 | Cualquier evento del honeypot (regla padre) |
| 100301 | 2 | Intento de login SSH. Está bajo el umbral de alerta por defecto (3), así que se cuenta pero no se muestra |
| 100302 | 10 | 8 intentos de login desde la misma IP en 60 s (T1110). `ignore="60"` limita las repeticiones |
| 100303 | 8 | Fuerza bruta lenta: 5 intentos de login desde la misma IP en 10 minutos (T1110) |
| 100310 | 8 | Intento de descarga desde la shell falsa (T1105) |
| 100320 | 12 | Archivo capturado que al menos un motor de VirusTotal marca como malicioso (T1105) |
| 100330 | 12 | Autenticación fallida en un sistema real desde una IP de la lista de atacantes del honeypot (T1110) |
| 100340 | 2 | Cualquier request HTTP (regla base del conjunto HTTP, se cuenta pero no se muestra) |
| 100341 | 8 | Request a `GponForm/diag_Form`, la ruta del exploit de routers GPON (T1190) |
| 100342 | 5 | Prueba de proxy abierto: una URL completa como ruta, o `CONNECT host:puerto` (T1595) |
| 100343 | 5 | Handshake T3 de WebLogic enviado al puerto HTTP (T1595.002) |
| 100344 | 3 | Tráfico que no es HTTP, como un protocolo perdido o basura binaria (T1595) |
| 100345 | 5 | Búsqueda de un objetivo conocido: `wp-json`, `wp-login`, `xmlrpc.php`, `/.env`, `/.git`, `phpmyadmin`, `actuator`, `/solr`, `manager/html`, Jenkins, GeoServer (T1595.002) |
| 100346 | 5 | 10 requests HTTP desde la misma IP en 120 s, `ignore="300"` (T1595) |
| 100347 | 4 | Login FTP como `anonymous` (T1078) |

La severidad sigue cuánta evidencia hay. Un intento de login o un GET simple es ruido, un request a una ruta de exploit muestra intención y una muestra que VirusTotal confirma es una prueba.

El honeypot HTTP también guarda el cuerpo del POST. Eso importa para la regla 100341: el exploit de GPON manda su comando en el cuerpo y no en la URL, y la ruta sola no dice qué quería ejecutar el atacante.

### Lista de IPs de atacantes (CDB)

`honeypot-attackers.example` muestra el formato (`ip:etiqueta`). Se instala como `/var/ossec/etc/lists/honeypot-attackers`, se registra `<list>etc/lists/honeypot-attackers</list>` en el bloque `<ruleset>` de `ossec.conf` y se reinicia el manager. La regla 100330 sube un login fallido desde una IP de la lista del nivel 5 de fábrica (`5760`) al nivel 12.

Estado: solo simulado. Probé la búsqueda y la prioridad de la regla con `wazuh-logtest`: una IP de la lista dio 100330 y una que no estaba dio 5760. La lista se llena a mano. Alimentarla desde las alertas 100302 y 100320 necesitaría un script y un reinicio del manager para recargarla. No lo construí.

### Lo que aprendí probando

- **Los archivos de reglas se cargan en orden alfabético.** Una regla hija (`if_sid`) tiene que ir después de su padre. Con el nombre equivocado, `wazuh-logtest` mostró advertencias y las reglas no hacían nada. Renombrar el archivo lo arregló.
- **El nombre del campo importa.** Mi primera versión usaba `event_type`, que chocaba con la regla de Suricata 86600. Cambiarlo a `honeypot_event` lo resolvió.
- **Las reglas de nivel 0 no cuentan para las reglas de frecuencia.** La regla base de login es de nivel 2 a propósito, para que 100302 pueda contarla. Lo mismo vale para 100340 y 100346.
- **`wazuh-logtest` no es producción.** Recarga las reglas en cada ejecución y el motor en marcha solo las carga al iniciar el manager. Las reglas pasaron en logtest y no produjeron nada en vivo hasta que reinicié el manager.
- **Los strings de JSON se cortan en un byte nulo.** Un request que empezaba con un carácter nulo llegó con el `method` vacío, porque el decodificador corta el string en `\u0000`. Por eso 100344 mira lo que el método no es, en vez de buscar basura conocida.
- **Las rutas con comodín encuentran los archivos nuevos tarde.** El agente detectó un archivo nuevo unos 40 s después de que apareció y solo leyó lo que vino después. Es una observación de dos pruebas, no un intervalo medido.
- **Los campos anidados de JSON usan puntos**, por ejemplo `virustotal.maliciosos`.
- **Las reglas de frecuencia agrupan por IP de origen, así que esa IP tiene que ser la real.** Docker publica los puertos a través de `docker-proxy`. Una redirección a ese puerto hace que todos los atacantes parezcan la dirección del bridge, y 100302, 100303 y 100346 los contarían a todos como uno solo. Para el puerto SSH reenvío con DNAT directo al contenedor, que conserva la dirección de origen real.
- **Limpiar tu propio tráfico de prueba lleva tres lugares.** Mis conexiones llegaron a los logs del honeypot, a los archivos de alertas de Wazuh y al indexador. Mi primera limpieza no hizo nada y me di cuenta solo porque conté después. Tras el segundo intento el conteo dio cero.

### Aislamiento de red

La instancia del honeypot tiene su propio security group. De entrada, los puertos del honeypot están abiertos a internet: 2222, 8080, 2121 y ahora 22 (más abajo). El tráfico de salida se limita a lo que el proyecto necesita:

| Puerto | Destino | Para qué |
|---|---|---|
| TCP 1514, 1515 | Solo el manager de Wazuh (/32) | Eventos del agente y enrolamiento |
| TCP 443 | Cualquiera | Consultas a VirusTotal y descargas de muestras por HTTPS |
| TCP 80 | Cualquiera | Descargas de muestras por HTTP |

Comprobado desde la instancia: 80 y 443 responden, los puertos 22 y 25 hacia internet dan timeout, 1514 al manager conecta, el agente sigue `Active` y el contenedor todavía llega a VirusTotal.

Límites, dichos sin vueltas:
- 80 y 443 tienen que quedar abiertos a cualquier destino porque el honeypot descarga la URL que el atacante escriba. El security group no puede distinguir eso de un request legítimo. La protección contra destinos internos está en el código (`url_es_segura`) y no cubre el DNS rebinding.
- Las descargas desde otros puertos, como el 8080, dan timeout a propósito. No probé cómo reporta ese error el código.
- Según la documentación de AWS (no probado acá): los security groups no filtran el tráfico al resolver DNS de la VPC, a los metadatos de la instancia ni al servicio de hora. El DNS queda entonces como una vía de salida que este control no puede cerrar. El acceso a los metadatos desde el contenedor se bloquea aparte (IMDSv2 con hop limit 1, sin rol de instancia).

### Primera noche expuesto

El honeypot estuvo unas 15 horas con los puertos 2222 (SSH falso), 8080 (HTTP falso) y 2121 (FTP falso) abiertos a internet. Es una muestra chica de una sola noche, así que es un caso de estudio y no estadística.

Qué llegó:
- 27 requests HTTP de unas nueve fuentes, casi todos GET simples sin credenciales. Varias fuentes mandaron ráfagas de 3 a 6 requests en pocos segundos, lo que apunta a scripts que prueban varias rutas.
- 3 intentos de login SSH, todos de una sola fuente, con `root` y `123456`, `password` y `12345678`.
- Ninguna descarga de malware ni comandos en la shell. Nadie pasó el login, que es lo esperable en un puerto no estándar.

Qué buscaban los sondeos HTTP:

| Ruta | Qué indica |
|---|---|
| `/` (19 veces) | "¿Hay algo escuchando?" El primer paso de cualquier scanner |
| `/wp-json`, `/license.txt` | Busca WordPress y su versión |
| `/hudson` | Busca un servidor Jenkins |
| `/login`, `/favicon.ico` | Búsqueda genérica de paneles de login y fingerprinting de productos |
| `http://a7x[.]overflow[.]biz/hachk.php` | Una URL completa mandada como ruta: prueba de proxy abierto. El honeypot no hace de proxy, así que no se descargó nada |

También llegaron dos payloads que no eran HTTP (un solo carácter árabe y un bloque de texto corto con `AS:2048`). No pude identificar el segundo, así que no adivino.

Nada se parecía a una explotación. Todo era reconocimiento (ATT&CK T1595, escaneo activo).

El hallazgo más útil fue la fuente SSH. Mandaba un intento cada 30 segundos más o menos. La regla 100302 necesita una ráfaga de intentos dentro de 60 segundos, así que este patrón nunca la hubiera disparado. Es una fuerza bruta lenta, y dejó a la vista un hueco en mi propia detección que solo encontré porque tuve tráfico real.

Lo cerré con la regla 100303 (5 intentos en 10 minutos, nivel 8). Probada de dos formas:
- En `wazuh-logtest`, 12 intentos seguidos: 100303 saltó en el evento 5 y 100302 en el 9. Interpreto el 9 como el octavo login contado, porque el 5 lo consumió 100303. Esa explicación es mi interpretación, la posición es la medición. Después de cada disparo los eventos siguientes volvieron a 100301, lo que es coherente con que `ignore` funcione.
- En vivo, 6 intentos separados por 30 segundos: exactamente una alerta, 100303, y ninguna 100302.

En una ráfaga rápida saltan las dos reglas, primero la de nivel 8 y después la de nivel 10, así que la severidad escala sola.

### Las reglas HTTP y FTP (100340 a 100347)

La primera noche mostró lo que mandan los scanners HTTP, pero la primera versión del pack solo tenía reglas de SSH. Escribí el conjunto HTTP después de leer lo que había llegado de verdad: intentos de exploit de GPON, sondeos de proxy abierto, un handshake de WebLogic en un puerto HTTP y la búsqueda de siempre de WordPress y Jenkins.

Cómo las comprobé:
- Cada una de las ocho reglas en `wazuh-logtest`, con un evento de ejemplo.
- En vivo, con tráfico real que llegó al honeypot y una prueba de ráfaga que generé yo.
- Por diseño, un `GET /` simple se queda en nivel 2: lo cuenta 100346, pero no llega al dashboard.

Límites:
- 100345 busca fragmentos de ruta. Una aplicación real que tenga una ruta `/solr` o `/.git` la dispararía, y es una lista que armé con lo que vi, no una lista completa.
- 100344 es de nivel 3, el más bajo que llega al dashboard. Todavía no sé si es más útil que ruidosa.
- 100347 trata cualquier login FTP anónimo como sospechoso. En un honeypot es razonable, en un servidor FTP real no.

### Puerto 22

El SSH falso solo escuchaba en el 2222, que los scanners casi nunca prueban primero. Abrí el puerto 22 a internet con una regla DNAT hacia el contenedor, y el `sshd` real de administración queda detrás, solo con clave. La regla no es persistente: después de un reinicio vuelve a responder el `sshd` real en el 22, que es la dirección segura en la que fallar.

Estado: recién abierto. Voy a agregar los resultados acá cuando junte uno o dos días de tráfico, incluyendo si las reglas SSH (100301, 100302, 100303) saltan de punta a punta con atacantes reales.

### Verificado y no verificado

Verificado de punta a punta con eventos sintéticos (IPs de documentación `203.0.113.x`): 100310, 100320, 100302 y 100303 llegan a `alerts.json`, y 100301 no (nivel 2, bajo el umbral de alerta de 3). Diez intentos de login desde una IP produjeron exactamente una alerta 100302.

Verificado en `wazuh-logtest` y en vivo: el conjunto HTTP y FTP, de 100340 a 100347.

Verificado después de apagar y prender las dos instancias: el contenedor del honeypot vuelve solo (`restart: unless-stopped`) y el agente se reconecta al manager.

Verificado solo en `wazuh-logtest`: 100330 y la búsqueda en la CDB (simulado, ver arriba).

No aislado: si `ignore="60"` suprime las repeticiones. La prueba mandó 10 intentos, que no alcanzan para una segunda ráfaga de 8, así que no distingue `ignore` del contador de frecuencia solo.

No verificado: si Filebeat manda alertas duplicadas al indexador después de acortar a mano un archivo de alertas, como hice al limpiar mi propio tráfico. Tampoco medido todavía: el comportamiento con tráfico SSH real en el puerto 22.
