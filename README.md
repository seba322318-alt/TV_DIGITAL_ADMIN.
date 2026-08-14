# TV DIGITAL · Backend + Panel Administrador

Proyecto sin dependencias externas. Requiere Node.js 20 o superior.

## Incluye

- Login compatible con la APK: `POST /auth/login`
- Verificación de sesión: `POST /auth/ping`
- Cierre de sesión: `POST /auth/logout`
- Catálogo protegido: `GET /content?type=TV|MOVIE|SERIES`
- Panel web en `/`
- Creación de clientes y pruebas de 24 horas
- Vencimientos, suspensión/activación, ampliación de días
- Límite de dispositivos y conexiones simultáneas
- Liberación de dispositivos
- Catálogo de TV, películas y series
- Contraseñas de clientes almacenadas con PBKDF2 + sal

## Probar en PC

1. Instala Node.js 20+.
2. Abre una terminal en esta carpeta.
3. Define las variables de administrador (recomendado) y ejecuta:

Windows PowerShell:

```powershell
$env:ADMIN_USER="admin"
$env:ADMIN_PASSWORD="TU_CLAVE_SEGURA"
node server.js
```

Luego abre `http://localhost:3000/`.

## Publicar

Sube esta carpeta a un repositorio GitHub separado. En el hosting usa:

- Start command: `node server.js`
- Variable `ADMIN_USER`: tu usuario administrador
- Variable `ADMIN_PASSWORD`: una contraseña fuerte
- Variable opcional `SESSION_HOURS`: `24`

IMPORTANTE: la base de datos está en `data/db.json`. En un hosting cuya unidad de disco sea efímera los datos pueden borrarse al reiniciar o redesplegar. Para producción usa un disco/volumen persistente o migra a PostgreSQL/Supabase.

## Conectar la APK

Después de publicar obtendrás una URL HTTPS, por ejemplo:

`https://tu-api.example.com/`

En el proyecto Android cambia el valor por defecto de `TV_DIGITAL_API_URL` en `app/build.gradle.kts`, o configura esa propiedad durante la compilación. La URL base debe terminar en `/`.

Ejemplo:

```kotlin
.orElse("https://tu-api.example.com/")
```

Luego vuelve a compilar el APK en Codemagic.

## Seguridad

- Cambia `ADMIN_PASSWORD` antes de publicar.
- No publiques credenciales reales dentro de GitHub.
- Usa siempre HTTPS fuera de tu red local.
- Agrega únicamente contenido y streams que tengas derecho a distribuir.
