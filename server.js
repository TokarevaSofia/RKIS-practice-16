const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'my_super_secret_key_123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } 
}));
const USERS_FILE = path.join(__dirname, 'users.json');
function loadUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      fs.writeFileSync(USERS_FILE, '[]', 'utf8');
      return [];
    }
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data || '[]');
  } catch (err) {
    console.error('Ошибка чтения users.json:', err);
    return [];
  }
}
function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) {
    console.error('Ошибка записи users.json:', err);
  }
}
let users = loadUsers();
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.redirect('/login');
}
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') {
    return next();
  }
  res.status(403).send('<h1>403: Доступ запрещен</h1><p>У вас нет прав для просмотра этой страницы.</p><a href="/">Вернуться на главную</a>');
}
app.get('/', (req, res) => {
  const currentUser = req.session.user || null;
  res.render('index', { user: currentUser });
});
app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('register', { error: null });
});
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('register', { error: 'Заполните все поля!' });
  }
  if (password.length < 6) {
    return res.render('register', { error: 'Пароль должен содержать минимум 6 символов!' });
  }
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.render('register', { error: 'Пользователь с таким именем уже существует!' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const role = users.length === 0 ? 'admin' : 'user';
  const newUser = {
    id: Date.now(),
    username: username,
    password: hashedPassword,
    role: role 
  };
  users.push(newUser);
  saveUsers(users);
  req.session.user = { id: newUser.id, username: newUser.username, role: newUser.role };
  res.redirect('/');
});
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', { error: null });
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  users = loadUsers();
  if (!username || !password) {
    return res.render('login', { error: 'Заполните все поля!' });
  }
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.render('login', { error: 'Неверное имя пользователя или пароль!' });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.render('login', { error: 'Неверное имя пользователя или пароль!' });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect('/');
});
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error(err);
    res.redirect('/');
  });
});
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  users = loadUsers(); 
  res.render('admin', { user: req.session.user, users: users });
});
app.post('/admin/delete/:id', requireAuth, requireAdmin, (req, res) => {
  const userIdToDelete = parseInt(req.params.id);
  const currentUserId = req.session.user.id;
  if (userIdToDelete === currentUserId) {
    return res.status(400).send('<h1>Ошибка</h1><p>Вы не можете удалить свой собственный аккаунт!</p><a href="/admin">Назад</a>');
  }
  users = loadUsers();
  users = users.filter(u => u.id !== userIdToDelete);
  saveUsers(users);
  res.redirect('/admin');
});
app.listen(PORT, () => {
  console.log(`Сервер запущен по адресу: http://localhost:${PORT}`);
});