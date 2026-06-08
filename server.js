// ===== 꿈비 인사이트 대시보드 백엔드 =====
// 로그인(아이디+비번 여러 명) + 데이터 저장(PostgreSQL) + 정적 파일 서빙
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1); // Railway는 프록시 뒤에 있음 (secure 쿠키용)
app.use(express.json({ limit: '5mb' }));

// ===== 세션 =====
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-railway',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Railway(HTTPS)에서 true
    maxAge: 1000 * 60 * 60 * 12 // 12시간
  }
}));

// ===== 사용자 계정 =====
// 환경변수 USERS = JSON 배열. 예:
// [{"id":"jini","pw":"$2a$10$...bcrypt해시..."},{"id":"manager","pw":"$2a$..."}]
// 비번 해시는 /gen-hash 로 만들 수 있음 (아래 참고).
let USERS = [];
try {
  USERS = JSON.parse(process.env.USERS || '[]');
} catch (e) {
  console.error('USERS 환경변수 파싱 실패. JSON 형식 확인.', e.message);
}

// ===== PostgreSQL =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway')
    ? { rejectUnauthorized: false } : false
});

// 테이블 준비 (key-value 저장소: notes, team 등)
async function initDB() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS kv_store (
      k TEXT PRIMARY KEY,
      v JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    )`);
    console.log('DB 테이블 준비 완료');
  } catch (e) {
    console.error('DB 초기화 실패:', e.message);
  }
}
initDB();

// ===== 인증 미들웨어 =====
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: '로그인이 필요합니다' });
}

// ===== 인증 API =====
app.post('/api/login', async (req, res) => {
  const { id, pw } = req.body || {};
  if (!id || !pw) return res.status(400).json({ error: '아이디/비밀번호 필요' });
  const user = USERS.find(u => u.id === id);
  if (!user) return res.status(401).json({ error: '인증 실패' });
  let ok = false;
  try { ok = await bcrypt.compare(pw, user.pw); } catch (e) {}
  if (!ok) return res.status(401).json({ error: '인증 실패' });
  req.session.userId = id;
  res.json({ ok: true, id });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.userId) return res.json({ id: req.session.userId });
  res.status(401).json({ error: '비로그인' });
});

// ===== 데이터 API (로그인 필수) =====
// 코멘트/전략
app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT v FROM kv_store WHERE k='soonNotes'");
    res.json(r.rows[0] ? r.rows[0].v : { comment: '', strategy: '' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    const v = { comment: req.body.comment || '', strategy: req.body.strategy || '' };
    await pool.query(
      `INSERT INTO kv_store(k,v,updated_at) VALUES('soonNotes',$1,now())
       ON CONFLICT(k) DO UPDATE SET v=$1, updated_at=now()`, [v]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 팀원 데이터
app.get('/api/team', requireAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT v FROM kv_store WHERE k='teamData'");
    res.json(r.rows[0] ? r.rows[0].v : { data: null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/team', requireAuth, async (req, res) => {
  try {
    const v = { data: req.body.data || null };
    await pool.query(
      `INSERT INTO kv_store(k,v,updated_at) VALUES('teamData',$1,now())
       ON CONFLICT(k) DO UPDATE SET v=$1, updated_at=now()`, [v]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== 비번 해시 생성 도우미 (최초 1회용) =====
// 브라우저에서 /gen-hash?pw=원하는비번 으로 접속하면 bcrypt 해시를 보여줌.
// 그 해시를 USERS 환경변수에 넣으면 됨. 보안을 위해 계정 세팅 후에는 GEN_HASH_ENABLE를 끄세요.
app.get('/gen-hash', async (req, res) => {
  if (process.env.GEN_HASH_ENABLE !== 'true') return res.status(403).send('비활성화됨 (GEN_HASH_ENABLE=true 필요)');
  const pw = req.query.pw;
  if (!pw) return res.send('사용법: /gen-hash?pw=원하는비밀번호');
  const hash = await bcrypt.hash(pw, 10);
  res.send(`<pre>비번: ${pw}\n해시: ${hash}\n\n이 해시를 USERS 환경변수의 "pw" 값에 넣으세요.</pre>`);
});

// ===== 정적 파일 (대시보드) =====
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`서버 실행 중: 포트 ${PORT}`));
