# Monitor UAF · publicación automática en GitHub Pages

Este repositorio contiene:

- `index.html`: dashboard estático.
- `monitor_uaf.py`: consulta fuentes públicas, clasifica hallazgos y genera `datos.json`.
- `construye_sitio.py`: prepara únicamente los archivos que se publican.
- `.github/workflows/actualizar-monitor.yml`: ejecuta el monitor cada 15 minutos y despliega GitHub Pages.
- `datos.json`: corte inicial del dashboard.
- `.monitor_estado.json`: huellas iniciales para no marcar el corte de ejemplo como nuevo.

## Arquitectura

GitHub Pages **no ejecuta Python** ni mantiene un proceso `--daemon`. El funcionamiento es:

1. GitHub Actions inicia una máquina temporal cada 15 minutos.
2. Recupera el estado de la rama técnica `monitor-state`.
3. Ejecuta una sola pasada de `monitor_uaf.py`.
4. Genera `datos.json` y una copia fresca del dashboard.
5. Publica `index.html` y `datos.json` mediante GitHub Pages.
6. Reemplaza la rama `monitor-state` con el último estado, sin llenar `main` de commits automáticos.

## Publicación inicial

### 1. Crear el repositorio

En GitHub crea un repositorio llamado, por ejemplo, `monitor-uaf`.

Para usar GitHub Pages gratuitamente, el repositorio debe ser público. **No subas información interna, credenciales, listas reservadas ni datos personales.** El dashboard y `datos.json` serán accesibles desde internet.

### 2. Subir esta carpeta

Con Git instalado, abre una terminal dentro de esta carpeta y ejecuta:

```bash
git init
git branch -M main
git add .
git commit -m "Publicar monitor UAF"
git remote add origin https://github.com/TU_USUARIO/monitor-uaf.git
git push -u origin main
```

En Windows también puedes ejecutar `publicar_github.bat` y pegar la URL del repositorio cuando la solicite.

### 3. Habilitar GitHub Pages

En el repositorio:

1. `Settings` → `Pages`.
2. En `Build and deployment`, selecciona **GitHub Actions** como fuente.
3. `Settings` → `Actions` → `General` → `Workflow permissions`.
4. Si el flujo falla al crear `monitor-state`, selecciona **Read and write permissions** y guarda.

### 4. Ejecutar la primera actualización

1. Abre la pestaña `Actions`.
2. Selecciona **Actualizar y publicar monitor**.
3. Pulsa `Run workflow`.
4. Revisa que termine con marcas verdes.
5. En `Settings` → `Pages` aparecerá la dirección publicada:
   `https://TU_USUARIO.github.io/monitor-uaf/`.

La ejecución programada usa los minutos `07`, `22`, `37` y `52` de cada hora. GitHub puede retrasarla cuando existe alta demanda; no debe interpretarse como una vigilancia en tiempo real exacto.

## Correo electrónico opcional

Primero deja que el flujo termine correctamente **con el correo desactivado**. Después crea los secretos en:

`Settings` → `Secrets and variables` → `Actions` → `New repository secret`.

| Secreto | Ejemplo |
|---|---|
| `MONITOR_CORREO_ACTIVO` | `true` |
| `MONITOR_SMTP_SERVIDOR` | `smtp.gmail.com` |
| `MONITOR_SMTP_PUERTO` | `587` |
| `MONITOR_SMTP_SEGURIDAD` | `starttls` |
| `MONITOR_SMTP_USUARIO` | `cuenta@dominio.cl` |
| `MONITOR_SMTP_CLAVE` | clave de aplicación o clave del relé |
| `MONITOR_DESTINATARIOS` | `uno@dominio.cl,dos@dominio.cl` |
| `MONITOR_REMITENTE_NOMBRE` | `Monitor UAF` |
| `MONITOR_MINIMO_AVISO` | `1` |
| `MONITOR_SILENCIO_MINUTOS` | `60` |
| `MONITOR_SOLO_UAF` | `true` |

`config.json` está excluido mediante `.gitignore`. Nunca guardes contraseñas dentro del código, el HTML o `datos.json`.

## Cambiar la frecuencia

Edita `.github/workflows/actualizar-monitor.yml`:

```yaml
schedule:
  - cron: "7,22,37,52 * * * *"
```

Ejemplos:

```yaml
# Cada 30 minutos
- cron: "7,37 * * * *"

# Una vez por hora
- cron: "17 * * * *"
```

Las expresiones programadas se interpretan en UTC, pero como este flujo corre todo el día, el huso no afecta la periodicidad. El script usa `America/Santiago` para fechar los registros y adapta automáticamente el horario de invierno/verano cuando se ejecuta con Python 3.11.

## Diagnóstico

En `Actions`, abre una ejecución y revisa el paso **Ejecutar monitor**.

Mensajes relevantes:

- `Listo: ... → datos.json`: ejecución correcta.
- `ninguna fuente respondió; se conserva el último datos.json`: caída de conectividad o bloqueo temporal; no se vacía el dashboard.
- `fallo en Google News`, `Reddit` o `Bluesky`: una fuente concreta no respondió.
- error en `Guardar estado`: revisa los permisos de escritura del workflow.
- error en `Publicar en GitHub Pages`: confirma que Pages usa **GitHub Actions** como fuente.

## Ejecución local

```bash
python monitor_uaf.py
python -m http.server 8000
```

Luego abre `http://localhost:8000`.

Para modo continuo local:

```bash
python monitor_uaf.py --daemon --intervalo 15
```
