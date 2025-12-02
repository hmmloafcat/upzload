import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import { formidable } from 'formidable';
import crypto from 'crypto';

const app = express();

const USERS_FILE = './users.json';
const UPLOAD_DIR = './uploads';

// Ensure uploads folder exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Load users.json or create empty
let users = {};
if (fs.existsSync(USERS_FILE)) {
  users = JSON.parse(fs.readFileSync(USERS_FILE));
} else {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(session({
  secret: 'supersecret',
  resave: false,
  saveUninitialized: false
}));

// Require login
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/');
}

// ===== SIGN UP =====
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('username and password required');
  if (users[username]) return res.send('username already exists');

  const hash = bcrypt.hashSync(password, 10);
  users[username] = { password_hash: hash };
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

  // Create user folder
  const userDir = path.join(UPLOAD_DIR, username);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

  // Auto-login
  req.session.userId = username;

  // Redirect to files page directly
  res.redirect('/files.html');
});

// ===== LOGIN =====
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user) return res.send('user not found');

  if (bcrypt.compareSync(password, user.password_hash)) {
    req.session.userId = username;
    res.redirect('/files.html');
  } else {
    res.send('incorrect password');
  }
});

// ===== LOGOUT =====
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ===== LIST FILES (per-user, per-upload folder) =====
function listFilesRecursive(dir) {
  const stats = fs.statSync(dir);
  if (!stats.isDirectory()) return [{ name: path.basename(dir), type: 'file' }];

  const files = [];
  for (const item of fs.readdirSync(dir)) {
    const fullPath = path.join(dir, item);
    const itemStats = fs.statSync(fullPath);
    if (itemStats.isDirectory()) {
      files.push({
        name: item,
        type: 'directory',
        children: listFilesRecursive(fullPath)
      });
    } else {
      files.push({ name: item, type: 'file', path: fullPath });
    }
  }
  return files;
}

app.get('/api/files', requireLogin, (req, res) => {
  const userDir = path.join(UPLOAD_DIR, req.session.userId);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

  const files = listFilesRecursive(userDir);
  res.json(files);
});

// ===== UPLOAD FILE =====
app.post('/api/upload', requireLogin, (req, res) => {
  const userDir = path.join(UPLOAD_DIR, req.session.userId);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

  // Create unique folder per upload
  const uploadFolderName = crypto.randomBytes(3).toString('hex'); // 6 chars
  const uploadPath = path.join(userDir, uploadFolderName);
  fs.mkdirSync(uploadPath, { recursive: true });

  const form = formidable({
    multiples: true,
    uploadDir: uploadPath,
    keepExtensions: true
  });

  form.parse(req, (err, fields, files) => {
    if (err) return res.status(500).send('upload failed');

    // Move all uploaded files to the uploadPath
    const fileKeys = Object.keys(files);
    if (fileKeys.length === 0) return res.status(400).send('no files uploaded');

    for (const key of fileKeys) {
      const file = files[key];
      const originalName = Array.isArray(file) ? file[0].originalFilename : file.originalFilename;
      const filepath = Array.isArray(file) ? file[0].filepath : file.filepath;
      const newPath = path.join(uploadPath, originalName);
      fs.renameSync(filepath, newPath);
    }

    // Create an index.html for the download page
    const indexHtmlPath = path.join(uploadPath, 'index.html');
    const downloadButtons = fileKeys.map((key, i) => {
      const fileObj = Array.isArray(files[key]) ? files[key][i] : files[key];
      return `<button onclick="window.location.href='/download/${req.session.userId}/${uploadFolderName}/${fileObj.originalFilename}'">download ${fileObj.originalFilename}</button>`;
    }).join('<br>');

    fs.writeFileSync(indexHtmlPath, `
      <!DOCTYPE html>
      <html lang="en">
      <head><meta charset="UTF-8"><title>upzload - download files</title></head>
      <body>
        <h1>download this shared file</h1>
        ${downloadButtons}
      </body>
      </html>
    `);

    res.send('upload successful');
  });
});

// ===== DOWNLOAD FILE =====
app.get('/download/:user/:folder/:filename', requireLogin, (req, res) => {
  const { user, folder, filename } = req.params;

  // Security: only allow user to download their own files
  if (req.session.userId !== user) return res.status(403).send('forbidden');

  const filePath = path.join(UPLOAD_DIR, user, folder, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('file not found');

  res.download(filePath);
});

// ===== START SERVER =====
app.listen(3000, () => console.log('server running at http://localhost:3000'));
