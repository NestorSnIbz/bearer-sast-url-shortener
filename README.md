# SafeLink: Auditoria SAST con Bearer CLI y Despliegue en Azure

Proyecto funcional desarrollado para la **Actividad Grupal 1** del curso Calidad y Pruebas de Software (UPT).

## Caracteristicas principales

1. **Aplicacion Web y API REST (`src/`)**: Servicio acortador de enlaces en Node.js y Express con cabeceras de seguridad (`helmet`), validacion de esquemas (`http:` y `https:`) contra redirecciones abiertas (`CWE-601`) y anonimizacion SHA-256 de direcciones IP para evitar fugas de informacion personal (`CWE-532`).
2. **Herramienta SAST (`Bearer CLI`)**: Integrada en `.github/workflows/ci-cd.yml` como alternativa de codigo abierto listada por **OWASP Source Code Analysis Tools**, enfocada en vulnerabilidades OWASP Top 10 y flujo de datos sensibles.
3. **Despliegue Automatizado**: Construccion de imagen Docker en GitHub Container Registry (`ghcr.io`) y publicacion continua en **Azure App Service** (`https://upt-awa-577.azurewebsites.net`).

## Ejecucion local

```bash
npm install
npm test
npm start
```

El servidor se inicia en `http://localhost:8080`.
