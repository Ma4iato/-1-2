# Процедура динамічного тестування безпеки (DAST) (Етап 5)

## 1. Інструментарій та запуск DAST
Для динамічного тестування запущеного вебпрототипу використовується **OWASP ZAP Baseline Scan** (`zaproxy/action-baseline@v0.13.0`).

### Варіант 1: Автоматизовано у GitHub Actions (`.github/workflows/dast.yml`)
1. Встановлюються залежності (`requirements.txt`), ініціалізується база даних (`python src/db.py`) та підіймається Flask-сервер на `http://127.0.0.1:5000`.
2. Після перевірки готовності сервісу (`curl`) запускається `OWASP ZAP Baseline` з активним павуком та базовими перевірками (`-a`).
3. Артефакти `report_html.html`, `report_md.md`, `report_json.json` та журнал сервера `flask.log` зберігаються у `zap-report`.

### Варіант 2: Локальний запуск (Docker)
```bash
docker-compose up -d --build
make zap
```
Локальний HTML-звіт зберігається у `reports/zap/zap.html`.

## 2. Класифікація знахідок DAST
У звітах OWASP ZAP результати групуються за рівнем ризику:
- **High:** критичні або високоризикові проблеми, що безпосередньо ведуть до компрометації (наприклад, активний XSS/SQLi, критичні помилки конфігурації).
- **Medium:** відсутні захисні механізми браузера/заголовки (`Content-Security-Policy`, `X-Frame-Options` / Anti-clickjacking, небезпечні атрибути cookie `SameSite`), що підвищують імовірність успішної атаки.
- **Low:** інформаційні або низькоризикові зауваження (`X-Content-Type-Options`, розкриття заголовка `Server`, відсутність `Permissions-Policy` тощо).
- **Informational:** загальні відомості про технологічний стек та відповіді.

## 3. Результати сканування (Baseline — до виправлень)

- **Посилання на запуск CI:** [DAST (ZAP Baseline) Run #1 (`63269f9`)](https://github.com/Ma4iato/-1-2/actions/runs/43230706836)
- **Зведена статистика (за `zap-report/report_md.md`):** High: **0**, Medium: **4**, Low: **6**, Informational: **8** (проскановано 6 ендпоінтів: 75% відповідей `2xx`, 25% `4xx`).

| Рівень критичності | Назва проблеми (Alert) | Кількість екземплярів | Короткий опис та вплив | Пов'язана вимога / Ризик |
|---|---|---|---|---|
| **Medium** | `Source Code Disclosure - SQL` (CWE-540) | 1 (`/search?q=test`) | Розкриття фрагмента SQL-запиту `SELECT id, title, body FROM posts WHERE title LIKE` безпосередньо в HTML-відповіді | `VAL-1` / `R1` |
| **Medium** | `Absence of Anti-CSRF Tokens` (CWE-352) | 2 (`/login` GET/POST) | Форма входу не містить анти-CSRF токена | `SESS-1` / `R5` |
| **Medium** | `Content Security Policy (CSP) Header Not Set` (CWE-693) | Systemic | Відсутній заголовок CSP, що полегшує експлуатацію XSS | `SESS-1` / `R2`, `R5` |
| **Medium** | `Missing Anti-clickjacking Header` (CWE-1021) | 5 | Відсутні `X-Frame-Options` / `frame-ancestors` у CSP | `SESS-1` / `R5` |
| **Low** | `X-Content-Type-Options Header Missing` (CWE-693) | 5 | Браузер може виконувати MIME-sniffing | `SESS-1` / `R5` |
| **Low** | `Server Leaks Version Information via "Server"` | Systemic | Заголовок `Server` розкриває `Werkzeug/3.1.9 Python/3.11.18` | `CONF-1` / `R4` |
| **Low** | `Cross-Origin-Embedder/Opener/Resource-Policy` та `Permissions-Policy` відсутні | 3 / Systemic | Відсутні сучасні заголовки браузерної ізоляції | `SESS-1` / `R5` |
| **Info** | `User Controllable HTML Element Attribute (Potential XSS)` | 1 (`/echo`) | Користувацький параметр `msg` віддзеркалюється у відповіді | `VAL-1` / `R2` |

> **Аналітична примітка:** `OWASP ZAP Baseline` виконує пасивний аналіз трафіку після павука (без активного фаззингу XSS/SQLi-векторів), тому Reflected XSS у `/echo` та SQLi у `/search` проявилися тут як `Potential XSS` (Info) і `Source Code Disclosure - SQL` (Medium), тоді як SAST (`Semgrep` і `Bandit`) впевнено класифікували їх як `Critical/High`. Це підтверджує необхідність комбінування SAST + DAST у SDLC.

## 4. Результати контрольного сканування (після виправлень)

- **Посилання на фінальний запуск CI (`main` після merge PR `#6`):** [DAST (ZAP Baseline) Run (`2baf051`)](https://github.com/Ma4iato/-1-2/actions/runs/43236139594)
- **Зведена статистика (за `zap-report/report_md.md`):** High: **0**, Medium: **1** (було 4), Low: **1** (було 6), Informational: **10**.
- **Підтверджені усунені проблеми:**
  - `Source Code Disclosure - SQL` (Medium) — **усунено**;
  - `Absence of Anti-CSRF Tokens` (Medium) — **усунено** (підтверджено `flask.log`: ZAP отримав `401` при тесті `/login`, спрацювало аудит-логування `security.audit: Failed login attempt username=ZAP ip=127.0.0.1`);
  - `Content Security Policy (CSP) Header Not Set` (Medium) та `Missing Anti-clickjacking Header` (Medium) — **усунено**;
  - `X-Content-Type-Options`, `Permissions-Policy`, `COEP`, `COOP`, `CORP` (Low) — **усунено**.
- **Залишкові знахідки (для наступної ітерації):**
  1. `CSP: Failure to Define Directive with No Fallback` (Medium) — у політиці CSP варто явно додати директиву `form-action 'self'`, оскільки вона не успадковується від `default-src`.
  2. `Server Leaks Version Information via "Server"` (Low) — вбудований сервер розробки `Werkzeug/3.1.9 Python/3.11.18` перезаписує заголовок `Server` на рівні WSGI-сокету; усувається переходом на production WSGI (`gunicorn`) за зворотним проксі Nginx.
