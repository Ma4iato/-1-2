# Підсумковий аудит безпеки SDLC (Етап 6)

**Репозиторій проєкту:** https://github.com/Ma4iato/-1-2  
**Модель SDLC:** DevSecOps  
**Дата фінального аудиту:** 12.11.2026

---

## 1. Перевірка виконання початкових вимог безпеки

| ID вимоги | Вимога | Початковий стан (`63269f9`) | Стан після PR `#6` (`2baf051`) | Підтвердження (код / тест / CI) |
|---|---|---|---|---|
| **AUTH-1** | Контроль доступу до `/profile` | Частково (слабкий `SECRET_KEY`) | **Виконано** | Перевірка `session["user_id"]` та наявності користувача в БД (`src/app.py`), тест `test_profile_requires_authentication` |
| **AUTH-2** | Захист від брутфорсу на `/login` | Відсутній | **Виконано** | Sliding-window rate limiter (5 невдалих спроб / 60 с → HTTP `429`), тест `test_login_rate_limiting` |
| **STOR-1** | Хешування паролів (PBKDF2/Argon2) | Порушено (plaintext) | **Виконано** | `generate_password_hash(..., method="pbkdf2:sha256")` у `src/db.py` + `check_password_hash` у `src/app.py`, тест `test_passwords_are_hashed_in_db` |
| **VAL-1** | Параметризовані SQL-запити та екранування HTML | Порушено (SQLi, XSS) | **Виконано** | Параметризований запит `?` у `/search`, `echo.html` з автоекрануванням Jinja2, Semgrep **0**, Bandit **0**, тести `test_sqli_is_blocked_in_search`, `test_reflected_xss_is_escaped_in_echo` |
| **SESS-1** | Прапорці cookie (`HttpOnly`, `SameSite`), CSRF та заголовки безпеки | Відсутні | **Виконано (із 1 залишковою порадою CSP)** | `HttpOnly=True`, `SameSite=Lax`, CSRF-токени на `/login` та `/logout`, CSP/XFO/XCTO/COOP/COEP/CORP, тест `test_security_headers_and_cookie_flags` |
| **LOG-1** | Аудит подій входу без секретів у логах | Відсутній | **Виконано** | Логер `security.audit` фіксує успішні/невдалі входи, `429` та CSRF-помилки (`flask.log` зафіксував спробу ZAP без витоку пароля) |
| **CONF-1** | Секрети в ENV/Secrets, вимкнений `debug=True` | Порушено | **Виконано** | Прибрано хардкод `SECRET_KEY` (генерація `secrets.token_hex(32)`), `debug=False`, `USER appuser` у `Dockerfile` |

---

## 2. Перегляд змін у коді та повідомлення про закриті вразливості

- **Базовий коміт (вразлива версія):** `63269f9` (`chore: init security baseline`)
  - Baseline SAST: [Run `43230706894`](https://github.com/Ma4iato/-1-2/actions/runs/43230706894) — Semgrep **23**, Bandit **3** (1 High, 2 Medium), `pip-audit` (**`flask==3.0.3` `PYSEC-2026-2151`**).
  - Baseline DAST: [Run `43230706836`](https://github.com/Ma4iato/-1-2/actions/runs/43230706836) — ZAP Alerts: High **0**, Medium **4**, Low **6**, Info **8**.
- **Гілка виправлень та Pull Request:** `fix/security-remediation` (`a73fdec`) → **[Pull Request #6](https://github.com/Ma4iato/-1-2/pull/6)**, злито в `main` комітом **`2baf051`**.
- **Контрольні прогони після злиття у `main`:**
  - SAST + Security Tests: [Run `43236139632`](https://github.com/Ma4iato/-1-2/actions/runs/43236139632) — **8/8 автотестів пройдено**, Semgrep **0**, Bandit **0**, `pip-audit` **0 вразливостей** (`flask==3.1.3`).
  - DAST (OWASP ZAP Baseline): [Run `43236139594`](https://github.com/Ma4iato/-1-2/actions/runs/43236139594) — High **0**, Medium **1** (було 4), Low **1** (було 6), Info **10**.

### Закриті задачі (GitHub Issues) та ризики (`risk-register.csv`)
- **Issue [#1](https://github.com/Ma4iato/-1-2/issues/1) (Closed in PR #6):** SQL Injection у `/search` та розкриття SQL (`R1`) → **Закрито**.
- **Issue [#2](https://github.com/Ma4iato/-1-2/issues/2) (Closed in PR #6):** Reflected XSS у `/echo` (`R2`) → **Закрито**.
- **Issue [#3](https://github.com/Ma4iato/-1-2/issues/3) (Closed in PR #6):** Plaintext паролі, відсутність rate limiting і аудиту входу (`R3`, `R7`) → **Закрито**.
- **Issue [#4](https://github.com/Ma4iato/-1-2/issues/4) (Closed in PR #6):** Захардкоджений `SECRET_KEY`, `debug=True`, `root` у Docker (`R4`) → **Закрито**.
- **Issue [#5](https://github.com/Ma4iato/-1-2/issues/5) (Closed in PR #6):** Anti-CSRF токени, заголовки безпеки та оновлення `flask==3.1.3` (`R5`, `R6`) → **Закрито** (із двома задокументованими низько-/помірноризиковими залишковими покращеннями: додати `form-action 'self'` у CSP та прибрати заголовок `Werkzeug` через production WSGI/Nginx).

---

## 3. Ролі учасників розробки та сегрегація обов'язків (Segregation of Duties)

Для усунення конфлікту інтересів (розробник не затверджує власний код у продакшен без незалежної перевірки) у моделі DevSecOps ролі розподілено таким чином:

| Роль у команді | Зона відповідальності в SDLC | Сегрегація обов'язків (обмеження) |
|---|---|---|
| **Product Owner (Owner)** | Визначення бізнес-цінності активів, затвердження початкових вимог безпеки (`requirements-security.md`), прийняття залишкових ризиків (`Risk Acceptance`) та пріоритезація security-задач у backlog. | Не втручається напряму в конфігурацію CI/CD та не обходить обов'язкові перевірки безпеки заради швидкого релізу без формального підпису ризику. |
| **Security Champion / AppSec** | Розробка моделі загроз (STRIDE), кастомних правил `.semgrep.yml`, налаштування політик тріажу SAST/DAST, валідація знахідок сканерів, аудит критичних PR та підготовка фінального аудиту. | Не пише основну бізнес-логіку фіч, які сам потім затверджує в контексті безпеки; виступає незалежним рецензентом security-змін. |
| **Developer (Dev)** | Реалізація функціоналу згідно з принципами Secure Coding (`VAL-1`, `STOR-1`, `AUTH-1/2`), виправлення підтверджених вразливостей у гілках `fix/*`, написання unit/security-тестів. | Не може самостійно злити свій PR у `main` (потрібне схвалення іншого рецензента та зелені перевірки CI SAST); не має доступу до продакшн-секретів. |
| **QA Engineer (QA)** | Написання та прогін функціональних і регресійних тестів, перевірка граничних випадків (негативні сценарії вводу на `/search`, `/echo`, `/login`), верифікація закриття багів після виправлень та супровід DAST-перевірок. | Не формує конфігурацію інфраструктури та продакшн-ключі; підтверджує працездатність захисту на тестовому стенді. |
| **DevOps / SecOps** | Підтримка репозиторію, налаштування захищених гілок (Branch Protection), конвеєрів GitHub Actions (`sast.yml`, `dast.yml`), контейнеризації (`Dockerfile`, `docker-compose.yml`), ізоляція та ротація секретів (`GitHub Secrets`). | Не змінює бізнес-логіку застосунку та не відключає SAST/DAST gates у пайплайні без узгодження з Security Champion і Product Owner. |

### Матриця RACI за етапами SDLC
*(R — Responsible / виконавець, A — Accountable / затверджувач, C — Consulted / консультант, I — Informed / поінформований)*

| Етап SDLC | Owner | Security Champion | Dev | QA | DevOps |
|---|---|---|---|---|---|
| 1. Ініціалізація та вимоги безпеки | **A** | **R** | C | C | I |
| 2. Моделювання загроз (STRIDE) | I | **A / R** | C | C | C |
| 3. Розробка та виправлення коду | I | C | **R** | I | I |
| 4. SAST / SCA у CI та тріаж | I | **A** | R | I | **R** (пайплайн) |
| 5. DAST (OWASP ZAP) та перевірка фіксів | I | C | R | **R** | **A** (стенд/CI) |
| 6. Підсумковий аудит і дозвіл на реліз | **A** | **R** | I | C | C |

---

## 4. Рекомендації щодо вдосконалення процесу безпеки

З урахуванням архітектури проєкту (легковаговий Python/Flask вебсервіс + SQLite) та моделі **DevSecOps** сформовано ітераційний план розвитку практик безпеки:

1. **Короткострокові покращення (Наступний спринт):**
   - **Закриття залишкових знахідок ZAP:** додати `form-action 'self'` до заголовка `Content-Security-Policy` у `src/app.py` (усуне останній Medium-алерт ZAP).
   - **Обов'язковий захист гілки `main` (Branch Protection):** заборонити прямі push у `main`, вимагати мінімум 1 review та проходження `SAST` workflow перед merge PR.
   - **Pre-commit хуки та Secret Scanning:** додати `gitleaks` у CI або увімкнути GitHub Secret Scanning для блокування коміту секретів на етапі розробки.
2. **Середньострокові покращення (1–2 місяці):**
   - **Production WSGI та зворотний проксі:** замінити вбудований сервер розробки Flask на `gunicorn` за Nginx/TLS-термінацією (усуне Low-алерт розкриття версії `Werkzeug/Python` у заголовку `Server`, дозволить увімкнути `SESSION_COOKIE_SECURE=True` та HSTS).
   - **GitHub CodeQL & Dependabot:** увімкнути CodeQL для міжпроцедурного taint-аналізу та Dependabot для автоматичних PR оновлення залежностей.
   - **Container & IaC Scanning (Trivy):** інтегрувати Trivy у CI для перевірки базового образу `python:3.11-slim` та `Dockerfile`.
3. **Довгострокові покращення (Зрілий DevSecOps):**
   - **Автоматизований DAST з автентифікацією (ZAP Full Scan):** налаштувати передачу сесії у ZAP для динамічного тестування захищених маршрутів (`/profile`, `/logout`) на staging-стенді.
   - **Централізований менеджмент секретів та SIEM:** перенести секрети в HashiCorp Vault / KMS, а логи `security.audit` експортувати в централізовану систему моніторингу (ELK / SIEM) з правилами алертингу на серії `401`/`403`/`429`.
