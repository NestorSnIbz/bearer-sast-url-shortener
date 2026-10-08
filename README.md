# SafeLink: Auditoria SAST con Bearer CLI y Despliegue en Vercel

Aplicacion web y API REST desarrollada para la **Actividad Grupal 1** (Calidad y Pruebas de Software - SI-784).

## Caracteristicas Principales

1. **Aplicacion Web y API REST (`src/`)**: Servicio acortador de enlaces en Node.js y Express protegido con cabeceras HTTP mediante `helmet`, validacion de protocolos (`http:` y `https:`) contra redirecciones abiertas (`CWE-601`), y enmascaramiento de direcciones IP con SHA-256 para evitar fugas de informacion en registros (`CWE-532`).
2. **Escaneo SAST y Flujo de Datos (`Bearer CLI`)**: Integrado en `.github/workflows/ci-cd.yml` como analizador estatico de codigo abierto incluido en la lista **OWASP Source Code Analysis Tools**, analizando vulnerabilidades OWASP Top 10 y flujos de datos confidenciales.
3. **Despliegue Automatizado en la Nube (Vercel)**: Configuracion Serverless en `vercel.json` y `api/index.js`, con despliegue automatizado hacia Vercel (`https://bearer-sast-url-shortener.vercel.app`).

## Ejecucion Local

```bash
npm install
npm test
npm start
```

El servidor local se ejecuta en `http://localhost:8080`.
