# Процедура статичного аналізу коду (SAST) та управління вразливостями (Етап 4)

## 1. Конвеєр SAST та SCA у CI/CD
Автоматизоване статичне сканування реалізовано у конвеєрі GitHub Actions [`.github/workflows/sast.yml`](../.github/workflows/sast.yml), який запускається автоматично на кожен `push`, `pull_request` та вручну через `workflow_dispatch`.

Інструменти в конвеєрі:
1. **Semgrep** (`--config auto --config .semgrep.yml`) — семантичний SAST-аналізатор, що поєднує стандартні набори правил із кастомними правилами проєкту в [`.semgrep.yml`](../.semgrep.yml):
   - `flask-sqli-fstring` (ERROR, CWE-89) — виявляє формування SQL-запитів через f-рядки у `cur.execute(...)`;
   - `flask-reflected-xss-fstring` (ERROR, CWE-79) — виявляє повернення HTML із підстановкою змінних без екранування у маршрутах Flask;
   - `flask-weak-hardcoded-secret` (WARNING, CWE-798) — виявляє захардкожені значення `app.secret_key`;
   - `flask-debug-enabled` (ERROR, CWE-489) — виявляє `debug=True` у `app.run(...)`.
2. **Bandit** (`bandit -r src`) — статичний аналізатор безпеки Python-коду (пошук `B608` SQLi, `B201` Flask debug, `B105/B106` захардкожених паролів/секретів тощо).
3. **pip-audit** — аналіз програмних компонентів (SCA) для перевірки `requirements.txt` на наявність відомих CVE.

## 2. Керування звітами сканерів
1. **Генерація артефактів:** після кожного запуску CI формується артефакт `sast-reports`, який містить:
   - `semgrep.sarif` та `semgrep.txt`;
   - `bandit.sarif` та `bandit.txt`;
   - `pip-audit.json` та `pip-audit.md`.
2. **Інтеграція у вкладку Security:** `semgrep.sarif` завантажується через `github/codeql-action/upload-sarif@v3` для відображення анотацій безпосередньо в коді Pull Request (для публічних репозиторіїв або при увімкненому Code Scanning).
3. **Архівування та рецензування:** Security Champion або DevOps-інженер завантажує артефакти з Actions run, звіряє знахідки з [`risk-register.csv`](risk-register.csv) та відсіює хибні спрацювання (False Positives) із документальним обґрунтуванням.

## 3. Тріаж, пріоритезація та SLA виправлень
Оцінювання знахідок виконується за трьома критеріями: **CVSS / критичність правила**, **реальна експлуатованість у контексті застосунку** та **вплив на активи (CIA)**.

| Рівень критичності | Критерії (SAST / SCA) | Максимальний SLA виправлення | Політика злиття (Quality Gate) |
|---|---|---|---|
| **Critical** | Пряме виконання коду / SQLi / компрометація секретів (CVSS ≥ 9.0) | 24–48 годин | Блокує реліз до закриття |
| **High** | XSS, небезпечний debug-режим, високі CVE з наявним експлойтом (CVSS 7.0–8.9) | До 7 календарних днів | Обов'язкове створення Issue + PR у поточному спринті |
| **Medium** | Відсутні захисні заголовки, слабкі налаштування cookie, помірні CVE (CVSS 4.0–6.9) | До 30 днів | Планується у backlog |
| **Low / Info** | Стиль коду, інформаційні зауваження (CVSS < 4.0) | На розсуд команди | Рекомендаційний характер |

## 4. Формування та відстеження задач у системі управління (GitHub Issues)
Для кожної підтвердженої знахідки рівня `Medium`, `High` або `Critical` створюється окрема задача (Issue) у **GitHub Issues** за єдиним шаблоном:

- **Мітки (Labels):** `security`, рівень критичності (`severity:critical` / `severity:high` / `severity:medium`), джерело (`sast` / `dast`).
- **Обов'язкові поля Issue:**
  1. Назва: `[SECURITY][<Severity>] <Короткий опис вразливості> (<CWE>)`.
  2. Локація у коді: точний файл та рядок (наприклад, `src/app.py:32`).
  3. Джерело виявлення: назва правила Semgrep/Bandit або посилання на артефакт CI.
  4. Кроки відтворення / потенційний вплив та прив'язка до ID ризику з `risk-register.csv`.
  5. Критерії приймання (Definition of Done): опис очікуваного виправлення, вимога додати автотест та пройти повторний SAST/DAST.
- **Відстеження життєвого циклу задачі:**
  `Open` (Issue створено) → `In Progress` (створено гілку `fix/issue-<N>-...`) → `In Review` (відкрито Pull Request із ключовим словом `Closes #<N>` та пройдено CI SAST/DAST) → `Verified / Closed` (PR злито, повторний звіт підтвердив відсутність знахідки, статус у `risk-register.csv` оновлено на `Closed`).

## 5. Результати первинного сканування SAST (Baseline)

- **Посилання на запуск CI:** [SAST Run #1 (`63269f9`)](https://github.com/Ma4iato/-1-2/actions/runs/43230706894)
- **Артефакти:** `sast-reports` (`semgrep.sarif`, `semgrep.txt`, `bandit.txt`, `pip-audit.json`, `pip-audit.md`)

| Інструмент | Знайдено | Основні знахідки | Прив'язка до ризику / задачі |
|---|---|---|---|
| **Semgrep** | 23 | `flask-sqli-fstring` (`src/app.py:32-33`), `raw-html-concat` / `directly-returned-format-string` (`src/app.py:24`), `flask-weak-hardcoded-secret` (`src/app.py:7`), `flask-debug-enabled` (`src/app.py:63`), `dockerfile.security.missing-user` (`Dockerfile:9`), `django-no-csrf-token` (`login.html:8`), mutable action tags (`.github/workflows/*.yml`) | `R1`, `R2`, `R4`, `R5`, `SEC-1..SEC-5` |
| **Bandit** | 3 (1 High, 2 Medium) | `B201: flask_debug_true` (`src/app.py:63`), `B608: hardcoded_sql_expressions` (`src/app.py:32`), `B104: hardcoded_bind_all_interfaces` (`src/app.py:63`) | `R1`, `R4` |
| **pip-audit** | 8 записів (1 у `requirements.txt`) | `flask==3.0.3` → `PYSEC-2026-2151` (оновити до `3.1.3`); решта (`mcp`, `opentelemetry-api`, `setuptools`) — пакети середовища CI-раннера | `R6` |

> **Примітка щодо тріажу:** у першому запуску `pip-audit` сканував усе Python-середовище після встановлення `semgrep`/`bandit`, тому до звіту потрапили транзитивні залежності інструментів CI (`mcp`, `opentelemetry-api`). У гілці виправлень команду оновлено на `pip-audit -r requirements.txt` для точного аудиту саме залежностей застосунку.

За результатами первинного сканування створено **5 задач у GitHub Issues** (`#1`–`#5`), які були пов'язані з гілкою `fix/security-remediation` та закриті через **Pull Request `#6`** (`Closes #1..#5`).

## 6. Результати контрольного сканування SAST (після виправлень)

- **Посилання на фінальний запуск CI (`main` після merge PR `#6`):** [SAST Run (`2baf051`)](https://github.com/Ma4iato/-1-2/actions/runs/43236139632)
- **Unit та Security тести (`tests/test_security.py`):** пройдено **8 / 8 тестів** (перевірка хешування паролів, захист від SQLi, екранування XSS, CSRF, rate limiting 429, заголовки безпеки, cookie-атрибути, захист `/profile`).
- **Semgrep:** **0 знахідок** (`semgrep.txt` порожній, зниження з **23 → 0**).
- **Bandit:** **0 знахідок** на 213 рядках коду (`No issues identified`, зниження з **3 → 0**).
- **pip-audit:** **0 вразливостей** серед усіх 34 залежностей (`flask==3.1.3`, `vulns: []`).
