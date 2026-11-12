# SDLC Security Demo Project (Flask)

Навчальний демонстраційний проєкт для практичної роботи **«Інтеграція безпеки в SDLC»**.
Модель розробки: **DevSecOps**.

## Швидкий старт (локально)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export FLASK_APP=src/app.py
export SECRET_KEY=dev-please-change-me
python src/db.py  # ініціалізація БД
flask run         # або: python src/app.py
```

Відкрийте: http://127.0.0.1:5000

## Структура
- `src/` — вихідний код Flask і шаблони Jinja2.
- `docs/` — артефакти безпеки за фазами SDLC:
  - [`docs/requirements-security.md`](docs/requirements-security.md) — початковий стан, вимоги безпеки та цілі (CIA);
  - [`docs/threat-model.md`](docs/threat-model.md) — модель загроз STRIDE, сценарії атак і виявлення;
  - [`docs/risk-register.csv`](docs/risk-register.csv) — реєстр ризиків;
  - [`docs/sast-process.md`](docs/sast-process.md) — процес SAST/SCA та управління задачами (Issues);
  - [`docs/dast-process.md`](docs/dast-process.md) — процес DAST (OWASP ZAP Baseline) та аналіз результатів;
  - [`docs/audit-report.md`](docs/audit-report.md) — підсумковий аудит, ролі команди (RACI) та рекомендації.
- `.semgrep.yml` — кастомні правила Semgrep для виявлення SQLi, XSS, слабких секретів та `debug=True`.
- `.github/workflows/` — CI з **SAST/SCA** (Semgrep, Bandit, pip-audit) і **DAST** (OWASP ZAP baseline).
- `Dockerfile`, `docker-compose.yml` — контейнеризація.
- `Makefile` — команди локального запуску та сканування.
- `SECURITY.md` — політика повідомлення про вразливості.

## Завдання студентів
Див. файл [`tasks.md`](tasks.md) — покроково для виконання і критерії оцінювання.
