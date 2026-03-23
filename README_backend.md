# FleetOS Backend v2.0

API REST multi-empresa para la plataforma FleetOS.

---

## Estructura del proyecto

```
fleeetos-backend/
├── server.js          ← API principal
├── package.json
├── .env.example       ← Copia como .env y configura
├── railway.toml       ← Config para Railway (deploy)
├── data/
│   └── fleetOS.db     ← Base de datos SQLite (se crea automático)
└── public/
    └── index.html     ← Coloca aquí el FlotaCargo_CRM_v5.html renombrado
```

---

## Instalación local

```bash
npm install
cp .env.example .env
# Edita .env con tu JWT_SECRET
node server.js
```

---

## Multi-empresa

Cada registro en todas las tablas tiene `company_id`.  
El sistema garantiza aislamiento total: cada empresa solo ve sus datos.

---

## Roles y permisos

| Rol           | Descripción                                      |
|---------------|--------------------------------------------------|
| superadmin    | Acceso global — gestiona empresas y todos los usuarios |
| Administrador | Gestión completa de su empresa                   |
| Supervisor    | Crear/editar operativos, sin borrar ni gestionar usuarios |
| Operador      | Solo lectura + registrar viajes y combustible    |

---

## Usuarios demo

| Email                         | Contraseña | Rol           | Empresa         |
|-------------------------------|------------|---------------|-----------------|
| superadmin@fleeetos.mx        | demo123    | superadmin    | (global)        |
| admin@flotacargo.mx           | demo123    | Administrador | FlotaCargo Demo |
| supervisor@flotacargo.mx      | demo123    | Supervisor    | FlotaCargo Demo |
| operador@flotacargo.mx        | demo123    | Operador      | FlotaCargo Demo |
| admin@transnorte.mx           | demo123    | Administrador | Transportes Norte |

---

## Endpoints principales

### Auth
```
POST /api/auth/login       { email, password } → { token, user, company }
GET  /api/auth/me          [auth] → usuario actual
POST /api/auth/logout      [auth]
```

### Empresas (solo superadmin)
```
GET    /api/companies
POST   /api/companies      { name, rfc, city, plan, logo_initials, brand_color }
PUT    /api/companies/:id
DELETE /api/companies/:id
```

### Usuarios
```
GET    /api/users                          Admin/superadmin
POST   /api/users          { name, email, password, role, company_id }
PUT    /api/users/:id      { name, role, active, custom_permissions }
PUT    /api/users/:id/password  { password }
DELETE /api/users/:id
```

### Flota, Operadores, Viajes, Combustible, Mantenimiento, Llantas
```
GET    /api/units
POST   /api/units
PUT    /api/units/:id
DELETE /api/units/:id

GET    /api/drivers
POST   /api/drivers
PUT    /api/drivers/:id
DELETE /api/drivers/:id
POST   /api/drivers/:id/incidents

GET    /api/trips
POST   /api/trips
PUT    /api/trips/:id
DELETE /api/trips/:id

GET    /api/fuel
POST   /api/fuel
DELETE /api/fuel/:id

GET    /api/maintenance
POST   /api/maintenance
PUT    /api/maintenance/:id
DELETE /api/maintenance/:id

GET    /api/tires
POST   /api/tires
PUT    /api/tires/:id
POST   /api/tires/:id/events
DELETE /api/tires/:id
```

### Dashboard y salud
```
GET /api/dashboard    [auth] → estadísticas de la empresa
GET /api/health              → status del servidor
```

---

## Deploy en Railway (recomendado)

1. Crea cuenta en [railway.app](https://railway.app)
2. Nuevo proyecto → Deploy from GitHub
3. Variables de entorno en Railway:
   - `JWT_SECRET` = (genera uno con `openssl rand -hex 32`)
   - `NODE_ENV` = `production`
4. En la carpeta `public/` pon el archivo HTML renombrado como `index.html`
5. El servidor sirve el frontend automáticamente

---

## Deploy en Render (gratis)

1. Crea cuenta en [render.com](https://render.com)
2. New Web Service → conecta GitHub
3. Build Command: `npm install`
4. Start Command: `node server.js`
5. Agrega variables de entorno igual que Railway

> ⚠️ Plan gratuito de Render se "duerme" tras 15 min de inactividad.

---

## Autenticación

Todas las rutas protegidas requieren:
```
Authorization: Bearer <token>
```

El token JWT contiene: `sub`, `email`, `name`, `role`, `company_id`, `avatar`

---

## Permisos granulares por usuario

El Administrador puede asignar permisos personalizados por módulo a cualquier usuario:

```json
{
  "trips": "rw",
  "fuel":  "r",
  "maintenance": "rw"
}
```

Se guardan en `users.custom_permissions` y el frontend los lee desde `user.custom_permissions`.
