#!/usr/bin/env node
// Инсталлятор скилла: копирует skill/ в пользовательскую папку скиллов Claude.
// Запускается через `npx github:fUS1ONd/snihunt`.
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const SKILL_NAME = 'snishka';
const src = path.join(__dirname, '..', 'skill');
const dest = path.join(os.homedir(), '.claude', 'skills', SKILL_NAME);

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const s = path.join(from, entry.name);
    const d = path.join(to, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

try {
  if (!fs.existsSync(src)) {
    console.error('Не найдена папка skill/ рядом с инсталлятором.');
    process.exit(1);
  }
  copyDir(src, dest);
  console.log('✓ Скилл установлен: ' + dest);
  console.log('  Перезапусти Claude Code, чтобы он подхватил скилл.');
} catch (e) {
  console.error('Ошибка установки: ' + e.message);
  process.exit(1);
}
