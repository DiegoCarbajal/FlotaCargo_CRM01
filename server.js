/**
 * FleetOS Backend v2.0
 * Multi-empresa · Roles granulares · JWT · SQLite
 * Node.js + Express + better-sqlite3 + bcryptjs
 */

'use strict';

const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const morgan   = require('morgan');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'CAMBIA_ESTE_SECRETO_EN_PRODUCCION';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '8h';
const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, 'data', 'fleetOS.db');
const NODE_ENV   = process.env.NODE_ENV   || 'development';

// Crear carpeta data si no existe
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// ─── PERMISOS POR ROL ────────────────────────────────────────────────────────
// superadmin → gestiona empresas y usuarios de cualquier empresa (plataforma)
// Administrador → gestiona su empresa completa
// Supervisor → lectura + crear/editar operativos, sin borrar ni gestionar usuarios
// Operador → solo lectura + registrar viajes/combustible propios
const ROLES = ['superadmin', 'Administrador', 'Supervisor', 'Operador'];

const PERMISSIONS = {
  // companies
  'companies:list':   ['superadmin'],
  'companies:create': ['superadmin'],
  'companies:edit':   ['superadmin'],
  'companies:delete': ['superadmin'],
  // users dentro de una empresa
  'users:list':       ['superadmin','Administrador'],
  'users:create':     ['superadmin','Administrador'],
  'users:edit':       ['superadmin','Administrador'],
  'users:delete':     ['superadmin','Administrador'],
  'users:change_role':['superadmin','Administrador'],
  // flota
  'units:list':       ['superadmin','Administrador','Supervisor','Operador'],
  'units:create':     ['superadmin','Administrador','Supervisor'],
  'units:edit':       ['superadmin','Administrador','Supervisor'],
  'units:delete':     ['superadmin','Administrador'],
  // operadores
  'drivers:list':     ['superadmin','Administrador','Supervisor','Operador'],
  'drivers:create':   ['superadmin','Administrador','Supervisor'],
  'drivers:edit':     ['superadmin','Administrador','Supervisor'],
  'drivers:delete':   ['superadmin','Administrador'],
  // viajes
  'trips:list':       ['superadmin','Administrador','Supervisor','Operador'],
  'trips:create':     ['superadmin','Administrador','Supervisor','Operador'],
  'trips:edit':       ['superadmin','Administrador','Supervisor','Operador'],
  'trips:delete':     ['superadmin','Administrador'],
  // combustible
  'fuel:list':        ['superadmin','Administrador','Supervisor','Operador'],
  'fuel:create':      ['superadmin','Administrador','Supervisor','Operador'],
  'fuel:delete':      ['superadmin','Administrador'],
  // mantenimiento
  'maintenance:list': ['superadmin','Administrador','Supervisor','Operador'],
  'maintenance:create':['superadmin','Administrador','Supervisor'],
  'maintenance:edit': ['superadmin','Administrador','Supervisor'],
  'maintenance:delete':['superadmin','Administrador'],
  // llantas
  'tires:list':       ['superadmin','Administrador','Supervisor','Operador'],
  'tires:create':     ['superadmin','Administrador','Supervisor'],
  'tires:edit':       ['superadmin','Administrador','Supervisor'],
  'tires:delete':     ['superadmin','Administrador'],
  // reportes y cierre
  'reports:view':     ['superadmin','Administrador','Supervisor'],
  'closing:edit':     ['superadmin','Administrador'],
};

function can(role, permission) {
  return (PERMISSIONS[permission] || []).includes(role);
}

// ─── BASE DE DATOS ───────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  -- ── EMPRESAS ──────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS companies (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    name        TEXT NOT NULL,
    rfc         TEXT,
    city        TEXT,
    plan        TEXT DEFAULT 'Demo',
    logo_initials TEXT,
    brand_color TEXT DEFAULT '#1447E6',
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── USUARIOS ──────────────────────────────────────────────────────────────
  -- Cada usuario pertenece a UNA empresa (company_id)
  -- superadmin puede tener company_id = NULL (acceso global)
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id  TEXT REFERENCES companies(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'Operador',
    avatar      TEXT,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login  DATETIME,
    -- Permisos personalizados por módulo (JSON: {"trips":"rw","fuel":"r",...})
    custom_permissions TEXT DEFAULT '{}'
  );

  -- ── FLOTA ─────────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS units (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id       TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    plates           TEXT NOT NULL,
    model            TEXT,
    year             INTEGER,
    trailer_type     TEXT,
    status           TEXT DEFAULT 'disponible',
    km               INTEGER DEFAULT 0,
    next_maint_km    INTEGER DEFAULT 0,
    doc_expiry       TEXT,
    fuel_eff         REAL DEFAULT 4.0,
    insurance_name   TEXT,
    insurance_expiry TEXT,
    notes            TEXT,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── OPERADORES ────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS drivers (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id  TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    estatus     TEXT DEFAULT 'activo',
    name        TEXT NOT NULL,
    license     TEXT,
    lic_expiry  TEXT,
    phone       TEXT,
    rfc         TEXT,
    address     TEXT,
    fuel_score  INTEGER DEFAULT 80,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── INCIDENCIAS ───────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id  TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    driver_id   TEXT NOT NULL REFERENCES drivers(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    date        TEXT,
    description TEXT,
    severity    TEXT DEFAULT 'warn',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── VIAJES ────────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS trips (
    id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id   TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    origin       TEXT,
    destination  TEXT,
    client       TEXT,
    cargo_type   TEXT,
    weight       REAL,
    depart_date  TEXT,
    arrival_date TEXT,
    unit_id      TEXT REFERENCES units(id),
    driver_id    TEXT REFERENCES drivers(id),
    status       TEXT DEFAULT 'programado',
    km           REAL,
    fuel_est     REAL,
    month        TEXT,
    revenue      REAL DEFAULT 0,
    driver_fee   REAL DEFAULT 0,
    fines        REAL DEFAULT 0,
    notes        TEXT,
    created_by   TEXT REFERENCES users(id),
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── COMBUSTIBLE ───────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS fuel_records (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id  TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    unit_id     TEXT REFERENCES units(id),
    driver_id   TEXT REFERENCES drivers(id),
    date        TEXT,
    liters      REAL,
    cost        REAL,
    location    TEXT,
    km          INTEGER,
    month       TEXT,
    created_by  TEXT REFERENCES users(id),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── MANTENIMIENTO ─────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS maintenance (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id  TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    unit_id     TEXT REFERENCES units(id),
    type        TEXT,
    category    TEXT,
    date        TEXT,
    cost        REAL DEFAULT 0,
    description TEXT,
    status      TEXT DEFAULT 'programado',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── LLANTAS ───────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS tires (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    company_id       TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    codigo           TEXT,
    marca            TEXT,
    modelo           TEXT,
    medida           TEXT,
    tipo             TEXT DEFAULT 'traccion',
    fecha_compra     TEXT,
    costo            REAL DEFAULT 0,
    proveedor        TEXT,
    vida_util_km     INTEGER DEFAULT 100000,
    unit_id          TEXT REFERENCES units(id),
    eje              INTEGER,
    lado             TEXT,
    km_instalacion   INTEGER DEFAULT 0,
    km_actual        INTEGER DEFAULT 0,
    status           TEXT DEFAULT 'activa',
    desgaste         TEXT DEFAULT 'normal',
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tire_events (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    tire_id     TEXT NOT NULL REFERENCES tires(id) ON DELETE CASCADE,
    company_id  TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    tipo        TEXT NOT NULL,
    fecha       TEXT,
    km          INTEGER,
    responsable TEXT,
    notas       TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ── ÍNDICES ───────────────────────────────────────────────────────────────
  CREATE INDEX IF NOT EXISTS idx_users_email      ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_company    ON users(company_id);
  CREATE INDEX IF NOT EXISTS idx_units_company    ON units(company_id);
  CREATE INDEX IF NOT EXISTS idx_drivers_company  ON drivers(company_id);
  CREATE INDEX IF NOT EXISTS idx_trips_company    ON trips(company_id);
  CREATE INDEX IF NOT EXISTS idx_trips_month      ON trips(company_id, month);
  CREATE INDEX IF NOT EXISTS idx_fuel_company     ON fuel_records(company_id);
  CREATE INDEX IF NOT EXISTS idx_maint_company    ON maintenance(company_id);
  CREATE INDEX IF NOT EXISTS idx_tires_company    ON tires(company_id);
  CREATE INDEX IF NOT EXISTS idx_tire_events      ON tire_events(tire_id);
`);

// ─── SEED DATOS DEMO ─────────────────────────────────────────────────────────
const seed = db.transaction(() => {
  if (db.prepare("SELECT id FROM companies WHERE id='CO_DEMO'").get()) return;

  // ── Empresa demo ──
  db.prepare(`INSERT INTO companies (id,name,rfc,city,plan,logo_initials,brand_color)
    VALUES ('CO_DEMO','FlotaCargo Demo S.A.','FCD000000XX0','Colima, México','Pro','FC','#1447E6')`).run();

  // ── Segunda empresa (para demostrar multi-empresa) ──
  db.prepare(`INSERT INTO companies (id,name,rfc,city,plan,logo_initials,brand_color)
    VALUES ('CO_NORTE','Transportes del Norte','TDN000000YY1','Monterrey, NL','Demo','TN','#0F6E56')`).run();

  const hash = bcrypt.hashSync('demo123', 10);

  // ── Superadmin (acceso global, sin empresa) ──
  db.prepare(`INSERT INTO users (id,company_id,name,email,password,role,avatar)
    VALUES ('USR_SUPER',NULL,'Super Admin','superadmin@fleeetos.mx',?,'superadmin','SA')`).run(hash);

  // ── Admin empresa demo ──
  db.prepare(`INSERT INTO users (id,company_id,name,email,password,role,avatar)
    VALUES ('USR_ADMIN','CO_DEMO','Admin FlotaCargo','admin@flotacargo.mx',?,'Administrador','AF')`).run(hash);

  // ── Supervisor empresa demo ──
  db.prepare(`INSERT INTO users (id,company_id,name,email,password,role,avatar)
    VALUES ('USR_SUP','CO_DEMO','Supervisor Demo','supervisor@flotacargo.mx',?,'Supervisor','SD')`).run(hash);

  // ── Operador empresa demo ──
  db.prepare(`INSERT INTO users (id,company_id,name,email,password,role,avatar)
    VALUES ('USR_OP','CO_DEMO','Operador Demo','operador@flotacargo.mx',?,'Operador','OD')`).run(hash);

  // ── Admin empresa norte ──
  db.prepare(`INSERT INTO users (id,company_id,name,email,password,role,avatar)
    VALUES ('USR_NORTE','CO_NORTE','Admin Norte','admin@transnorte.mx',?,'Administrador','AN')`).run(hash);

  // ── Unidades CO_DEMO ──
  const units = [
    ['U001','CO_DEMO','TRC-2401','Kenworth T680',2021,'Refrigerado','disponible',142350,150000,'2025-08-15',4.2,'GNP Seguros','2025-09-30'],
    ['U002','CO_DEMO','TRC-1892','Peterbilt 579',2020,'Plataforma','en ruta',218700,220000,'2025-12-01',3.9,'AXA Seguros','2025-07-15'],
    ['U003','CO_DEMO','TRC-3307','Freightliner Cascadia',2022,'Caja Seca','mantenimiento',89200,100000,'2025-11-20',4.5,'Mapfre','2026-02-28'],
    ['U004','CO_DEMO','TRC-0054','International LT625',2019,'Tanque','disponible',315000,320000,'2025-03-10',3.7,'',''],
  ];
  const insU = db.prepare(`INSERT INTO units (id,company_id,plates,model,year,trailer_type,status,km,next_maint_km,doc_expiry,fuel_eff,insurance_name,insurance_expiry) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  units.forEach(r => insU.run(...r));

  // ── Unidades CO_NORTE ──
  db.prepare(`INSERT INTO units (id,company_id,plates,model,year,status,km,fuel_eff) VALUES (?,?,?,?,?,?,?,?)`)
    .run('UN001','CO_NORTE','NOR-1000','Volvo FH16',2022,'disponible',55000,4.1);

  // ── Operadores CO_DEMO ──
  const drivers = [
    ['D001','CO_DEMO','activo','Carlos Mendoza Ríos','TRA-001234','2026-06-30','+52 312 100 0001','MERC850312AB1','Av. Vallarta 1234, Guadalajara',92],
    ['D002','CO_DEMO','activo','Javier Torres Gutiérrez','TRA-005678','2025-11-15','+52 312 100 0002','TOGJ780910CD3','Calle Reforma 567, Monterrey',78],
    ['D003','CO_DEMO','activo','Miguel Ángel Ruiz','TRA-009012','2026-02-28','+52 312 100 0003','RUIM901215EF5','Blvd. Díaz Ordaz 890, Guadalajara',97],
    ['D004','CO_DEMO','baja','Roberto Sánchez Pérez','TRA-003456','2025-09-01','+52 312 100 0004','SAPE750628GH7','Calzada Independencia 321, Guadalajara',71],
  ];
  const insD = db.prepare(`INSERT INTO drivers (id,company_id,estatus,name,license,lic_expiry,phone,rfc,address,fuel_score) VALUES (?,?,?,?,?,?,?,?,?,?)`);
  drivers.forEach(r => insD.run(...r));

  // ── Incidencias ──
  db.prepare(`INSERT INTO incidents (id,company_id,driver_id,type,date,description,severity) VALUES (?,?,?,?,?,?,?)`)
    .run('I001','CO_DEMO','D001','Infracción','2025-01-15','Exceso de velocidad 115 km/h','warn');
  db.prepare(`INSERT INTO incidents (id,company_id,driver_id,type,date,description,severity) VALUES (?,?,?,?,?,?,?)`)
    .run('I002','CO_DEMO','D002','Accidente','2025-01-10','Colisión menor en reversa','danger');

  // ── Viajes CO_DEMO ──
  const trips = [
    ['V001','CO_DEMO','Guadalajara','Monterrey','Bimbo S.A.','Alimentos',18500,'2025-01-10','2025-01-11','U002','D002','en curso',890,213,'2025-01',28500,2200,0],
    ['V002','CO_DEMO','CDMX','Cancún','OXXO Corp.','Bebidas',22000,'2025-01-12','2025-01-14','U001','D001','programado',1620,386,'2025-01',52000,3800,0],
    ['V003','CO_DEMO','Colima','Tijuana','Aceros del Norte','Acero',28000,'2025-01-08','2025-01-10','U004','D004','finalizado',2350,635,'2025-01',74000,5200,1500],
    ['V004','CO_DEMO','Manzanillo','CDMX','Samsung México','Electrónicos',12000,'2025-01-07','2025-01-08','U003','D003','cancelado',720,160,'2025-01',0,0,0],
    ['V005','CO_DEMO','Monterrey','Guadalajara','Cemex S.A.','Cemento',25000,'2025-02-03','2025-02-04','U001','D001','finalizado',890,212,'2025-02',31000,2600,0],
    ['V006','CO_DEMO','Guadalajara','CDMX','Grupo Bimbo','Alimentos',19000,'2025-02-08','2025-02-09','U002','D002','finalizado',540,138,'2025-02',18500,1800,800],
  ];
  const insT = db.prepare(`INSERT INTO trips (id,company_id,origin,destination,client,cargo_type,weight,depart_date,arrival_date,unit_id,driver_id,status,km,fuel_est,month,revenue,driver_fee,fines) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  trips.forEach(r => insT.run(...r));

  // ── Combustible CO_DEMO ──
  const fuel = [
    ['F001','CO_DEMO','U001','D001','2025-01-09',450,9450,'Pemex Gdl Norte',141200,'2025-01'],
    ['F002','CO_DEMO','U002','D002','2025-01-10',500,10500,'Pemex Aguascalientes',218100,'2025-01'],
    ['F003','CO_DEMO','U004','D004','2025-01-08',600,12600,'Pemex Gdl Sur',314200,'2025-01'],
    ['F004','CO_DEMO','U001','D001','2025-02-05',480,10080,'Pemex Zapotlanejo',142850,'2025-02'],
    ['F005','CO_DEMO','U002','D002','2025-02-07',520,10920,'Pemex CDMX Norte',219300,'2025-02'],
  ];
  const insF = db.prepare(`INSERT INTO fuel_records (id,company_id,unit_id,driver_id,date,liters,cost,location,km,month) VALUES (?,?,?,?,?,?,?,?,?,?)`);
  fuel.forEach(r => insF.run(...r));

  // ── Mantenimiento CO_DEMO ──
  const maint = [
    ['M001','CO_DEMO','U003','Correctivo','Frenos','2025-01-05',8500,'Cambio de balatas y ajuste ABS','en proceso'],
    ['M002','CO_DEMO','U001','Preventivo','Aceite','2025-01-03',3200,'Cambio de aceite 15W-40 y filtros','completado'],
    ['M003','CO_DEMO','U002','Preventivo','Motor','2025-01-15',15000,'Revisión general de motor','programado'],
  ];
  const insM = db.prepare(`INSERT INTO maintenance (id,company_id,unit_id,type,category,date,cost,description,status) VALUES (?,?,?,?,?,?,?,?,?)`);
  maint.forEach(r => insM.run(...r));

  console.log('✅ Seed completado — 2 empresas, 5 usuarios demo');
});
seed();

// ─── EXPRESS ─────────────────────────────────────────────────────────────────
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

// Sirve el frontend desde /public
app.use(express.static(path.join(__dirname, 'public')));

// SPA fallback: rutas no-API devuelven index.html
app.get(/^(?!\/api).*/, (req, res) => {
  const idx = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(idx)) return res.sendFile(idx);
  res.send('FleetOS API corriendo. Sube el frontend a /public/');
});

// ─── MIDDLEWARES ─────────────────────────────────────────────────────────────

// Verifica JWT y carga req.user
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// Verifica permiso sobre un recurso
function perm(permission) {
  return (req, res, next) => {
    if (!can(req.user.role, permission))
      return res.status(403).json({
        error: 'Sin permiso para esta acción',
        required: permission,
        yourRole: req.user.role
      });
    next();
  };
}

// Para endpoints de empresa: inyecta company_id del token (no del body)
// superadmin puede pasar ?company_id=X para operar en otra empresa
function companyScope(req, res, next) {
  if (req.user.role === 'superadmin') {
    req.companyId = req.query.company_id || req.body.company_id || null;
  } else {
    req.companyId = req.user.company_id;
  }
  next();
}

// Helper: genera ID simple
const newId = (prefix = '') => prefix + Date.now().toString(36).toUpperCase();

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'Correo y contraseña requeridos' });

  const user = db.prepare(`
    SELECT u.*,
           c.id   AS co_id,
           c.name AS co_name,
           c.rfc  AS co_rfc,
           c.city AS co_city,
           c.plan AS co_plan,
           c.logo_initials AS co_logo,
           c.brand_color   AS co_color
    FROM users u
    LEFT JOIN companies c ON u.company_id = c.id
    WHERE lower(u.email) = lower(?) AND u.active = 1
  `).get(email.trim());

  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Credenciales incorrectas' });

  if (user.company_id && !user.co_id)
    return res.status(403).json({ error: 'Empresa inactiva o eliminada' });

  db.prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?').run(user.id);

  const token = jwt.sign({
    sub:        user.id,
    email:      user.email,
    name:       user.name,
    role:       user.role,
    company_id: user.company_id,
    avatar:     user.avatar
  }, JWT_SECRET, { expiresIn: JWT_EXPIRY });

  res.json({
    token,
    user: {
      id:     user.id,
      name:   user.name,
      email:  user.email,
      role:   user.role,
      avatar: user.avatar || user.name.slice(0,2).toUpperCase(),
      custom_permissions: JSON.parse(user.custom_permissions || '{}')
    },
    company: user.company_id ? {
      id:    user.co_id,
      name:  user.co_name,
      rfc:   user.co_rfc,
      city:  user.co_city,
      plan:  user.co_plan,
      logo:  user.co_logo,
      color: user.co_color
    } : null
  });
});

// GET /api/auth/me
app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.avatar, u.last_login, u.custom_permissions,
           c.id AS co_id, c.name AS co_name, c.plan, c.brand_color AS co_color
    FROM users u LEFT JOIN companies c ON u.company_id = c.id
    WHERE u.id = ?
  `).get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ ...user, custom_permissions: JSON.parse(user.custom_permissions || '{}') });
});

// POST /api/auth/logout  (stateless, solo confirmación)
app.post('/api/auth/logout', auth, (_req, res) => {
  res.json({ message: 'Sesión cerrada' });
});

// ─── EMPRESAS (superadmin) ───────────────────────────────────────────────────

// GET /api/companies
app.get('/api/companies', auth, perm('companies:list'), (req, res) => {
  const rows = db.prepare(`
    SELECT c.*,
           COUNT(DISTINCT u.id) AS user_count,
           COUNT(DISTINCT n.id) AS unit_count
    FROM companies c
    LEFT JOIN users u ON u.company_id = c.id
    LEFT JOIN units n ON n.company_id = c.id
    GROUP BY c.id ORDER BY c.name
  `).all();
  res.json(rows);
});

// POST /api/companies
app.post('/api/companies', auth, perm('companies:create'), (req, res) => {
  const { name, rfc, city, plan, logo_initials, brand_color } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre requerido' });
  const id = newId('CO');
  db.prepare(`INSERT INTO companies (id,name,rfc,city,plan,logo_initials,brand_color)
    VALUES (?,?,?,?,?,?,?)`).run(id, name, rfc||'', city||'', plan||'Demo',
    logo_initials || name.slice(0,2).toUpperCase(), brand_color||'#1447E6');
  res.status(201).json({ id, name });
});

// PUT /api/companies/:id
app.put('/api/companies/:id', auth, perm('companies:edit'), (req, res) => {
  const { name, rfc, city, plan, brand_color, active } = req.body;
  db.prepare(`UPDATE companies SET
    name=COALESCE(?,name), rfc=COALESCE(?,rfc), city=COALESCE(?,city),
    plan=COALESCE(?,plan), brand_color=COALESCE(?,brand_color),
    active=COALESCE(?,active) WHERE id=?`)
    .run(name, rfc, city, plan, brand_color, active, req.params.id);
  res.json({ message: 'Empresa actualizada' });
});

// DELETE /api/companies/:id
app.delete('/api/companies/:id', auth, perm('companies:delete'), (req, res) => {
  db.prepare('DELETE FROM companies WHERE id=?').run(req.params.id);
  res.json({ message: 'Empresa eliminada' });
});

// ─── USUARIOS ────────────────────────────────────────────────────────────────

// GET /api/users  — admin ve su empresa, superadmin puede ver todas
app.get('/api/users', auth, perm('users:list'), companyScope, (req, res) => {
  let rows;
  if (req.user.role === 'superadmin' && !req.companyId) {
    rows = db.prepare(`
      SELECT u.id, u.name, u.email, u.role, u.avatar, u.active,
             u.created_at, u.last_login, u.custom_permissions,
             c.name AS company_name, c.id AS company_id
      FROM users u LEFT JOIN companies c ON u.company_id = c.id
      ORDER BY c.name, u.name
    `).all();
  } else {
    rows = db.prepare(`
      SELECT id, name, email, role, avatar, active,
             created_at, last_login, custom_permissions, company_id
      FROM users WHERE company_id=? ORDER BY name
    `).all(req.companyId);
  }
  res.json(rows.map(r => ({
    ...r,
    custom_permissions: JSON.parse(r.custom_permissions || '{}')
  })));
});

// POST /api/users
app.post('/api/users', auth, perm('users:create'), companyScope, (req, res) => {
  const { name, email, password, role, company_id } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Nombre, correo y contraseña requeridos' });
  if (!ROLES.includes(role))
    return res.status(400).json({ error: `Rol inválido. Válidos: ${ROLES.join(', ')}` });

  // Solo superadmin puede crear superadmins
  if (role === 'superadmin' && req.user.role !== 'superadmin')
    return res.status(403).json({ error: 'Solo superadmin puede crear superadmins' });

  const cid = req.user.role === 'superadmin' ? (company_id || null) : req.companyId;

  if (db.prepare('SELECT id FROM users WHERE lower(email)=lower(?)').get(email))
    return res.status(409).json({ error: 'El correo ya está registrado' });

  const id     = newId('USR');
  const hash   = bcrypt.hashSync(password, 10);
  const avatar = name.split(' ').slice(0,2).map(w => w[0]).join('').toUpperCase();
  db.prepare(`INSERT INTO users (id,company_id,name,email,password,role,avatar)
    VALUES (?,?,?,?,?,?,?)`).run(id, cid, name, email.trim(), hash, role, avatar);
  res.status(201).json({ id, name, email, role, avatar });
});

// PUT /api/users/:id  — editar nombre, rol, estado, permisos personalizados
app.put('/api/users/:id', auth, perm('users:edit'), companyScope, (req, res) => {
  const { name, role, active, custom_permissions } = req.body;

  // Validar que el usuario pertenece a la empresa (excepto superadmin)
  if (req.user.role !== 'superadmin') {
    const target = db.prepare('SELECT company_id FROM users WHERE id=?').get(req.params.id);
    if (!target || target.company_id !== req.companyId)
      return res.status(404).json({ error: 'Usuario no encontrado' });
  }
  if (role && !ROLES.includes(role))
    return res.status(400).json({ error: 'Rol inválido' });

  const cp = custom_permissions ? JSON.stringify(custom_permissions) : undefined;

  db.prepare(`UPDATE users SET
    name=COALESCE(?,name),
    role=COALESCE(?,role),
    active=COALESCE(?,active),
    custom_permissions=COALESCE(?,custom_permissions)
    WHERE id=?`).run(name, role, active, cp, req.params.id);

  res.json({ message: 'Usuario actualizado' });
});

// PUT /api/users/:id/password
app.put('/api/users/:id/password', auth, (req, res) => {
  const isSelf  = req.user.sub === req.params.id;
  const isAdmin = ['superadmin','Administrador'].includes(req.user.role);
  if (!isSelf && !isAdmin)
    return res.status(403).json({ error: 'Sin permiso para cambiar esta contraseña' });

  const { password } = req.body;
  if (!password || password.length < 6)
    return res.status(400).json({ error: 'Mínimo 6 caracteres' });

  db.prepare('UPDATE users SET password=? WHERE id=?')
    .run(bcrypt.hashSync(password, 10), req.params.id);
  res.json({ message: 'Contraseña actualizada' });
});

// DELETE /api/users/:id
app.delete('/api/users/:id', auth, perm('users:delete'), (req, res) => {
  if (req.params.id === req.user.sub)
    return res.status(400).json({ error: 'No puedes eliminar tu propio usuario' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ message: 'Usuario eliminado' });
});

// ─── FLOTA ───────────────────────────────────────────────────────────────────

app.get('/api/units', auth, perm('units:list'), companyScope, (req, res) => {
  res.json(db.prepare('SELECT * FROM units WHERE company_id=? ORDER BY plates')
    .all(req.companyId));
});

app.post('/api/units', auth, perm('units:create'), companyScope, (req, res) => {
  const u = req.body;
  const id = newId('UN');
  db.prepare(`INSERT INTO units (id,company_id,plates,model,year,trailer_type,status,km,next_maint_km,doc_expiry,fuel_eff,insurance_name,insurance_expiry,notes)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, req.companyId, u.plates, u.model, u.year||null,
         u.trailerType||u.trailer_type||'',
         u.status||'disponible', u.km||0,
         u.nextMaintKm||u.next_maint_km||0,
         u.docExpiry||u.doc_expiry||'',
         u.fuelEff||u.fuel_eff||4.0,
         u.insuranceName||u.insurance_name||'',
         u.insuranceExpiry||u.insurance_expiry||'',
         u.notes||'');
  res.status(201).json({ id });
});

app.put('/api/units/:id', auth, perm('units:edit'), companyScope, (req, res) => {
  const u = req.body;
  db.prepare(`UPDATE units SET
    plates=COALESCE(?,plates), model=COALESCE(?,model), year=COALESCE(?,year),
    trailer_type=COALESCE(?,trailer_type), status=COALESCE(?,status),
    km=COALESCE(?,km), next_maint_km=COALESCE(?,next_maint_km),
    doc_expiry=COALESCE(?,doc_expiry), fuel_eff=COALESCE(?,fuel_eff),
    insurance_name=COALESCE(?,insurance_name),
    insurance_expiry=COALESCE(?,insurance_expiry),
    notes=COALESCE(?,notes), updated_at=CURRENT_TIMESTAMP
    WHERE id=? AND company_id=?`)
    .run(u.plates, u.model, u.year,
         u.trailerType||u.trailer_type, u.status, u.km,
         u.nextMaintKm||u.next_maint_km,
         u.docExpiry||u.doc_expiry,
         u.fuelEff||u.fuel_eff,
         u.insuranceName||u.insurance_name,
         u.insuranceExpiry||u.insurance_expiry,
         u.notes, req.params.id, req.companyId);
  res.json({ message: 'Unidad actualizada' });
});

app.delete('/api/units/:id', auth, perm('units:delete'), companyScope, (req, res) => {
  db.prepare('DELETE FROM units WHERE id=? AND company_id=?')
    .run(req.params.id, req.companyId);
  res.json({ message: 'Unidad eliminada' });
});

// ─── OPERADORES ──────────────────────────────────────────────────────────────

app.get('/api/drivers', auth, perm('drivers:list'), companyScope, (req, res) => {
  const drivers   = db.prepare('SELECT * FROM drivers WHERE company_id=? ORDER BY name').all(req.companyId);
  const incidents = db.prepare('SELECT * FROM incidents WHERE company_id=?').all(req.companyId);
  res.json(drivers.map(d => ({
    ...d,
    licExpiry:  d.lic_expiry,
    fuelScore:  d.fuel_score,
    incidents:  incidents.filter(i => i.driver_id === d.id)
                .map(i => ({ id:i.id, type:i.type, date:i.date, desc:i.description, sev:i.severity }))
  })));
});

app.post('/api/drivers', auth, perm('drivers:create'), companyScope, (req, res) => {
  const d = req.body;
  const id = newId('DR');
  db.prepare(`INSERT INTO drivers (id,company_id,estatus,name,license,lic_expiry,phone,rfc,address,fuel_score) VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(id, req.companyId, d.estatus||'activo', d.name, d.license||'',
         d.licExpiry||d.lic_expiry||'', d.phone||'', d.rfc||'',
         d.address||'', d.fuelScore||d.fuel_score||80);
  res.status(201).json({ id });
});

app.put('/api/drivers/:id', auth, perm('drivers:edit'), companyScope, (req, res) => {
  const d = req.body;
  db.prepare(`UPDATE drivers SET
    estatus=COALESCE(?,estatus), name=COALESCE(?,name),
    license=COALESCE(?,license), lic_expiry=COALESCE(?,lic_expiry),
    phone=COALESCE(?,phone), rfc=COALESCE(?,rfc), address=COALESCE(?,address),
    fuel_score=COALESCE(?,fuel_score), updated_at=CURRENT_TIMESTAMP
    WHERE id=? AND company_id=?`)
    .run(d.estatus, d.name, d.license, d.licExpiry||d.lic_expiry,
         d.phone, d.rfc, d.address, d.fuelScore||d.fuel_score,
         req.params.id, req.companyId);
  res.json({ message: 'Operador actualizado' });
});

app.delete('/api/drivers/:id', auth, perm('drivers:delete'), companyScope, (req, res) => {
  db.prepare('DELETE FROM drivers WHERE id=? AND company_id=?').run(req.params.id, req.companyId);
  res.json({ message: 'Operador eliminado' });
});

// Incidencias
app.post('/api/drivers/:id/incidents', auth, perm('drivers:edit'), companyScope, (req, res) => {
  const i = req.body;
  const id = newId('INC');
  db.prepare(`INSERT INTO incidents (id,company_id,driver_id,type,date,description,severity) VALUES (?,?,?,?,?,?,?)`)
    .run(id, req.companyId, req.params.id, i.type, i.date, i.description||i.desc||'', i.severity||i.sev||'warn');
  res.status(201).json({ id });
});

// ─── VIAJES ──────────────────────────────────────────────────────────────────

app.get('/api/trips', auth, perm('trips:list'), companyScope, (req, res) => {
  const rows = db.prepare('SELECT * FROM trips WHERE company_id=? ORDER BY depart_date DESC').all(req.companyId);
  res.json(rows.map(t => ({
    ...t,
    unit:       t.unit_id,
    driver:     t.driver_id,
    departDate: t.depart_date,
    arrivalDate:t.arrival_date,
    cargoType:  t.cargo_type,
    driverFee:  t.driver_fee,
    fuelEst:    t.fuel_est
  })));
});

app.post('/api/trips', auth, perm('trips:create'), companyScope, (req, res) => {
  const t = req.body;
  const id = newId('VJ');
  db.prepare(`INSERT INTO trips (id,company_id,origin,destination,client,cargo_type,weight,depart_date,arrival_date,unit_id,driver_id,status,km,fuel_est,month,revenue,driver_fee,fines,notes,created_by)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, req.companyId, t.origin, t.destination, t.client,
         t.cargoType||t.cargo_type||'', t.weight||0,
         t.departDate||t.depart_date||'',
         t.arrivalDate||t.arrival_date||'',
         t.unit||t.unit_id||null, t.driver||t.driver_id||null,
         t.status||'programado', t.km||0,
         t.fuelEst||t.fuel_est||0,
         t.month||'', t.revenue||0,
         t.driverFee||t.driver_fee||0,
         t.fines||0, t.notes||'', req.user.sub);
  res.status(201).json({ id });
});

app.put('/api/trips/:id', auth, perm('trips:edit'), companyScope, (req, res) => {
  const t = req.body;
  db.prepare(`UPDATE trips SET
    origin=COALESCE(?,origin), destination=COALESCE(?,destination),
    client=COALESCE(?,client), status=COALESCE(?,status),
    arrival_date=COALESCE(?,arrival_date),
    km=COALESCE(?,km), fuel_est=COALESCE(?,fuel_est),
    revenue=COALESCE(?,revenue), driver_fee=COALESCE(?,driver_fee),
    fines=COALESCE(?,fines), notes=COALESCE(?,notes),
    updated_at=CURRENT_TIMESTAMP WHERE id=? AND company_id=?`)
    .run(t.origin, t.destination, t.client, t.status,
         t.arrivalDate||t.arrival_date,
         t.km, t.fuelEst||t.fuel_est,
         t.revenue, t.driverFee||t.driver_fee,
         t.fines, t.notes, req.params.id, req.companyId);
  res.json({ message: 'Viaje actualizado' });
});

app.delete('/api/trips/:id', auth, perm('trips:delete'), companyScope, (req, res) => {
  db.prepare('DELETE FROM trips WHERE id=? AND company_id=?').run(req.params.id, req.companyId);
  res.json({ message: 'Viaje eliminado' });
});

// ─── COMBUSTIBLE ─────────────────────────────────────────────────────────────

app.get('/api/fuel', auth, perm('fuel:list'), companyScope, (req, res) => {
  res.json(db.prepare('SELECT * FROM fuel_records WHERE company_id=? ORDER BY date DESC').all(req.companyId));
});

app.post('/api/fuel', auth, perm('fuel:create'), companyScope, (req, res) => {
  const f = req.body;
  const id = newId('FC');
  db.prepare(`INSERT INTO fuel_records (id,company_id,unit_id,driver_id,date,liters,cost,location,km,month,created_by)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, req.companyId, f.unit||f.unit_id||null, f.driver||f.driver_id||null,
         f.date||'', f.liters||0, f.cost||0, f.location||'',
         f.km||0, f.month||'', req.user.sub);
  res.status(201).json({ id });
});

app.delete('/api/fuel/:id', auth, perm('fuel:delete'), companyScope, (req, res) => {
  db.prepare('DELETE FROM fuel_records WHERE id=? AND company_id=?').run(req.params.id, req.companyId);
  res.json({ message: 'Registro eliminado' });
});

// ─── MANTENIMIENTO ───────────────────────────────────────────────────────────

app.get('/api/maintenance', auth, perm('maintenance:list'), companyScope, (req, res) => {
  res.json(db.prepare('SELECT * FROM maintenance WHERE company_id=? ORDER BY date DESC').all(req.companyId));
});

app.post('/api/maintenance', auth, perm('maintenance:create'), companyScope, (req, res) => {
  const m = req.body;
  const id = newId('MT');
  db.prepare(`INSERT INTO maintenance (id,company_id,unit_id,type,category,date,cost,description,status)
    VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(id, req.companyId, m.unit||m.unit_id||null, m.type||'', m.category||'',
         m.date||'', m.cost||0, m.description||'', m.status||'programado');
  res.status(201).json({ id });
});

app.put('/api/maintenance/:id', auth, perm('maintenance:edit'), companyScope, (req, res) => {
  const m = req.body;
  db.prepare(`UPDATE maintenance SET
    status=COALESCE(?,status), cost=COALESCE(?,cost),
    description=COALESCE(?,description), date=COALESCE(?,date),
    updated_at=CURRENT_TIMESTAMP WHERE id=? AND company_id=?`)
    .run(m.status, m.cost, m.description, m.date, req.params.id, req.companyId);
  res.json({ message: 'Mantenimiento actualizado' });
});

app.delete('/api/maintenance/:id', auth, perm('maintenance:delete'), companyScope, (req, res) => {
  db.prepare('DELETE FROM maintenance WHERE id=? AND company_id=?').run(req.params.id, req.companyId);
  res.json({ message: 'Registro eliminado' });
});

// ─── LLANTAS ─────────────────────────────────────────────────────────────────

app.get('/api/tires', auth, perm('tires:list'), companyScope, (req, res) => {
  const tires  = db.prepare('SELECT * FROM tires WHERE company_id=? ORDER BY codigo').all(req.companyId);
  const events = db.prepare('SELECT * FROM tire_events WHERE company_id=? ORDER BY fecha DESC').all(req.companyId);
  res.json(tires.map(t => ({
    ...t,
    vidaUtilKm:    t.vida_util_km,
    fechaCompra:   t.fecha_compra,
    kmInstalacion: t.km_instalacion,
    kmActual:      t.km_actual,
    unitId:        t.unit_id,
    eventos:       events.filter(e => e.tire_id === t.id)
  })));
});

app.post('/api/tires', auth, perm('tires:create'), companyScope, (req, res) => {
  const t = req.body;
  const id = newId('LL');
  db.prepare(`INSERT INTO tires (id,company_id,codigo,marca,modelo,medida,tipo,fecha_compra,costo,proveedor,vida_util_km,unit_id,eje,lado,km_instalacion,km_actual,status,desgaste)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, req.companyId, t.codigo||id, t.marca||'', t.modelo||'',
         t.medida||'295/80R22.5', t.tipo||'traccion',
         t.fechaCompra||t.fecha_compra||'',
         t.costo||0, t.proveedor||'',
         t.vidaUtilKm||t.vida_util_km||100000,
         t.unitId||t.unit_id||null, t.eje||null, t.lado||null,
         t.kmInstalacion||t.km_instalacion||0,
         t.kmActual||t.km_actual||0,
         t.status||'activa', t.desgaste||'normal');
  res.status(201).json({ id });
});

app.put('/api/tires/:id', auth, perm('tires:edit'), companyScope, (req, res) => {
  const t = req.body;
  db.prepare(`UPDATE tires SET
    marca=COALESCE(?,marca), modelo=COALESCE(?,modelo), medida=COALESCE(?,medida),
    unit_id=COALESCE(?,unit_id), eje=COALESCE(?,eje), lado=COALESCE(?,lado),
    km_actual=COALESCE(?,km_actual), status=COALESCE(?,status),
    desgaste=COALESCE(?,desgaste), updated_at=CURRENT_TIMESTAMP
    WHERE id=? AND company_id=?`)
    .run(t.marca, t.modelo, t.medida,
         t.unitId||t.unit_id, t.eje, t.lado,
         t.kmActual||t.km_actual, t.status, t.desgaste,
         req.params.id, req.companyId);
  res.json({ message: 'Llanta actualizada' });
});

app.post('/api/tires/:id/events', auth, perm('tires:edit'), companyScope, (req, res) => {
  const e = req.body;
  const id = newId('EV');
  db.prepare(`INSERT INTO tire_events (id,tire_id,company_id,tipo,fecha,km,responsable,notas)
    VALUES (?,?,?,?,?,?,?,?)`)
    .run(id, req.params.id, req.companyId, e.tipo||'Inspección',
         e.fecha||'', e.km||0, e.responsable||'', e.notas||'');

  // Si es cambio definitivo, marcar llanta como baja
  if (e.tipo === 'Cambio definitivo') {
    db.prepare("UPDATE tires SET status='baja', unit_id=NULL, eje=NULL, lado=NULL WHERE id=?")
      .run(req.params.id);
  }
  res.status(201).json({ id });
});

app.delete('/api/tires/:id', auth, perm('tires:delete'), companyScope, (req, res) => {
  db.prepare('DELETE FROM tires WHERE id=? AND company_id=?').run(req.params.id, req.companyId);
  res.json({ message: 'Llanta eliminada' });
});

// ─── DASHBOARD STATS ─────────────────────────────────────────────────────────

app.get('/api/dashboard', auth, perm('reports:view'), companyScope, (req, res) => {
  const cid = req.companyId;
  if (!cid) return res.status(400).json({ error: 'Se requiere company_id' });

  const s = (sql, ...args) => db.prepare(sql).get(cid, ...args);

  res.json({
    units_total:    s('SELECT COUNT(*) AS n FROM units WHERE company_id=?').n,
    units_active:   s("SELECT COUNT(*) AS n FROM units WHERE company_id=? AND status='en ruta'").n,
    trips_finished: s("SELECT COUNT(*) AS n FROM trips WHERE company_id=? AND status='finalizado'").n,
    trips_active:   s("SELECT COUNT(*) AS n FROM trips WHERE company_id=? AND status='en curso'").n,
    fuel_cost:      s('SELECT COALESCE(SUM(cost),0) AS n FROM fuel_records WHERE company_id=?').n,
    maint_cost:     s('SELECT COALESCE(SUM(cost),0) AS n FROM maintenance WHERE company_id=?').n,
    avg_fuel_eff:   s('SELECT COALESCE(AVG(fuel_eff),0) AS n FROM units WHERE company_id=?').n,
    drivers_active: s("SELECT COUNT(*) AS n FROM drivers WHERE company_id=? AND estatus='activo'").n,
    tires_at_risk:  s("SELECT COUNT(*) AS n FROM tires WHERE company_id=? AND status='activa' AND CAST(km_actual-km_instalacion AS REAL)/NULLIF(vida_util_km,0) >= 0.8").n,
  });
});

// ─── HEALTH CHECK ────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({
    status:  'ok',
    version: '2.0.0',
    env:     NODE_ENV,
    time:    new Date().toISOString()
  });
});

// ─── 404 / ERROR HANDLER ─────────────────────────────────────────────────────

app.use((req, res) => {
  if (req.path.startsWith('/api'))
    return res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.path}` });
  res.status(404).send('Not found');
});

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('❌', err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ─── START ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🚛  FleetOS API v2.0 — http://localhost:${PORT}`);
  console.log(`    Env:  ${NODE_ENV}`);
  console.log(`    DB:   ${DB_PATH}`);
  console.log(`\n    Usuarios demo:`);
  console.log(`    superadmin@fleeetos.mx  / demo123  (superadmin - acceso global)`);
  console.log(`    admin@flotacargo.mx     / demo123  (Administrador - CO_DEMO)`);
  console.log(`    supervisor@flotacargo.mx/ demo123  (Supervisor - CO_DEMO)`);
  console.log(`    operador@flotacargo.mx  / demo123  (Operador - CO_DEMO)`);
  console.log(`    admin@transnorte.mx     / demo123  (Administrador - CO_NORTE)\n`);
});

module.exports = app;
