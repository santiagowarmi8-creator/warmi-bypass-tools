# Bypass Tools — servidor propio

Backend compatible con el login de Bypass Tools y una página web sencilla.

## Variables de entorno

- `APP_USERNAME`: usuario permitido.
- `APP_PASSWORD`: contraseña permitida.
- `CORS_ORIGINS`: orígenes permitidos para la página web.

La contraseña debe configurarse como secreto en Render; no debe guardarse en GitHub.

## Endpoints

- `GET /health`
- `POST /user/auth/` con `username`, `password` y `mac_adress`.

La respuesta del login conserva el formato que espera la aplicación: `active` y `auth`.
