#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prueba SMTP independiente para Monitor UAF Chile.

Lee la misma configuración utilizada por el monitor desde variables de entorno,
valida cada etapa y termina rápidamente con mensajes de error claros.
No ejecuta el barrido de prensa ni modifica datos.json o monitor-state.
"""

from __future__ import annotations

import os
import socket
import smtplib
import ssl
import sys
import time
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid


def env_bool(nombre: str, defecto: bool = False) -> bool:
    valor = os.getenv(nombre)
    if valor is None or not valor.strip():
        return defecto
    return valor.strip().lower() in {"1", "true", "si", "sí", "yes", "on"}


def obligatorio(nombre: str) -> str:
    valor = (os.getenv(nombre) or "").strip()
    if not valor:
        raise ValueError(f"Falta configurar el secret {nombre}")
    return valor


def ocultar_correo(correo: str) -> str:
    if "@" not in correo:
        return "***"
    usuario, dominio = correo.split("@", 1)
    visible = usuario[:1] if usuario else ""
    return f"{visible}***@{dominio}"


def main() -> int:
    inicio = time.monotonic()
    print("=== Prueba independiente de correo · Monitor UAF ===", flush=True)

    if not env_bool("MONITOR_CORREO_ACTIVO"):
        raise ValueError(
            "MONITOR_CORREO_ACTIVO no está en true. La prueba se detiene porque "
            "el envío automático tampoco estaría habilitado."
        )

    servidor = obligatorio("MONITOR_SMTP_SERVIDOR")
    puerto_txt = obligatorio("MONITOR_SMTP_PUERTO")
    seguridad = obligatorio("MONITOR_SMTP_SEGURIDAD").lower()
    usuario = obligatorio("MONITOR_SMTP_USUARIO")
    clave = obligatorio("MONITOR_SMTP_CLAVE")
    destinatarios_txt = obligatorio("MONITOR_DESTINATARIOS")
    remitente_nombre = (os.getenv("MONITOR_REMITENTE_NOMBRE") or "Monitor UAF Chile").strip()

    try:
        puerto = int(puerto_txt)
    except ValueError as exc:
        raise ValueError("MONITOR_SMTP_PUERTO debe ser un número, por ejemplo 587") from exc

    if seguridad not in {"starttls", "ssl", "ninguna", "none"}:
        raise ValueError("MONITOR_SMTP_SEGURIDAD debe ser starttls, ssl o ninguna")

    destinatarios = [x.strip() for x in destinatarios_txt.replace(";", ",").split(",") if x.strip()]
    if not destinatarios:
        raise ValueError("MONITOR_DESTINATARIOS no contiene correos válidos")

    # Google muestra las contraseñas de aplicación agrupadas con espacios.
    # Gmail espera el código continuo; para otros servidores se conserva tal cual.
    if servidor.lower() in {"smtp.gmail.com", "smtp.googlemail.com"}:
        clave = clave.replace(" ", "")

    print(f"Servidor: {servidor}:{puerto}", flush=True)
    print(f"Seguridad: {seguridad}", flush=True)
    print(f"Usuario: {ocultar_correo(usuario)}", flush=True)
    print(f"Destinatarios: {len(destinatarios)}", flush=True)

    print("1/4 Resolviendo DNS...", flush=True)
    direcciones = socket.getaddrinfo(servidor, puerto, type=socket.SOCK_STREAM)
    if not direcciones:
        raise OSError(f"No se pudo resolver {servidor}")
    print("DNS correcto.", flush=True)

    msg = EmailMessage()
    msg["Subject"] = "Prueba de correo · Monitor UAF Chile"
    msg["From"] = formataddr((remitente_nombre, usuario))
    msg["To"] = ", ".join(destinatarios)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(
        "La configuración SMTP del Monitor UAF Chile está operativa.\n\n"
        f"Fecha de prueba: {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
        "Esta prueba no ejecutó el barrido de prensa ni modificó el dashboard.\n"
    )

    contexto = ssl.create_default_context()
    timeout = 15

    try:
        print("2/4 Abriendo conexión SMTP...", flush=True)
        if seguridad == "ssl":
            with smtplib.SMTP_SSL(servidor, puerto, context=contexto, timeout=timeout) as smtp:
                print("Conexión SSL correcta.", flush=True)
                print("3/4 Autenticando...", flush=True)
                smtp.login(usuario, clave)
                print("Autenticación correcta.", flush=True)
                print("4/4 Enviando mensaje...", flush=True)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(servidor, puerto, timeout=timeout) as smtp:
                smtp.ehlo()
                print("Conexión SMTP correcta.", flush=True)
                if seguridad == "starttls":
                    print("Negociando STARTTLS...", flush=True)
                    smtp.starttls(context=contexto)
                    smtp.ehlo()
                    print("STARTTLS correcto.", flush=True)
                print("3/4 Autenticando...", flush=True)
                smtp.login(usuario, clave)
                print("Autenticación correcta.", flush=True)
                print("4/4 Enviando mensaje...", flush=True)
                smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        detalle = exc.smtp_error.decode(errors="replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
        print(f"ERROR DE AUTENTICACIÓN SMTP ({exc.smtp_code}): {detalle}", file=sys.stderr, flush=True)
        print(
            "Para Gmail usa una contraseña de aplicación de 16 caracteres, no la contraseña normal. "
            "La cuenta debe tener verificación en dos pasos.",
            file=sys.stderr,
            flush=True,
        )
        return 31
    except smtplib.SMTPRecipientsRefused as exc:
        print(f"DESTINATARIOS RECHAZADOS: {list(exc.recipients)}", file=sys.stderr, flush=True)
        return 32
    except (socket.timeout, TimeoutError) as exc:
        print(
            f"TIEMPO DE ESPERA AGOTADO al conectar con {servidor}:{puerto}. "
            "Revisa servidor, puerto y seguridad.",
            file=sys.stderr,
            flush=True,
        )
        return 33
    except smtplib.SMTPException as exc:
        print(f"ERROR SMTP: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 34
    except OSError as exc:
        print(f"ERROR DE RED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 35

    print(f"Correo enviado correctamente en {time.monotonic() - inicio:.1f} segundos.", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"ERROR DE CONFIGURACIÓN: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(20)
