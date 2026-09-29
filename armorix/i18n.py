"""Uzbek / Russian / English output. Rule explanations are hand-written (not model-generated) so they are always accurate."""

from __future__ import annotations

import os

from .finding import Finding, Severity

LANGS = ("uz", "ru", "en")

# rule id → lang → (title, why it matters, how to fix)
RULES: dict[str, dict[str, tuple[str, str, str]]] = {
    "ARX-SQLI": {
        "uz": ("SQL in'ektsiya",
               "SQL so'rovi satrlarni qo'shish orqali yig'ilgan — hujumchi kiritgan qiymat so'rovning o'zini o'zgartirib, butun bazani o'qishi, o'zgartirishi yoki o'chirishi mumkin.",
               'Parametrli so\'rovdan foydalaning: db.query("... WHERE id = ?", [id]) / cursor.execute("... = %s", (id,)).'),
        "ru": ("SQL-инъекция",
               "SQL-запрос собирается склейкой строк — введённое значение меняет сам запрос: чтение, изменение или удаление всей базы.",
               'Используйте параметры: db.query("... WHERE id = ?", [id]) / cursor.execute("... = %s", (id,)).'),
        "en": ("SQL injection", "", ""),
    },
    "ARX-NOSQL": {
        "uz": ("NoSQL in'ektsiya",
               'So\'rov maydonlari to\'g\'ridan-to\'g\'ri MongoDB so\'roviga berilyapti — {"$ne": null} kabi operator bilan parol tekshiruvini aylanib o\'tish mumkin.',
               "Har bir maydonni kerakli turga keltiring (String(req.body.email)) yoki zod / joi sxemasi bilan tekshiring."),
        "ru": ("NoSQL-инъекция",
               'Поля запроса передаются в MongoDB как есть — оператором вида {"$ne": null} можно обойти проверку пароля.',
               "Приводите поля к нужному типу (String(req.body.email)) или валидируйте схемой (zod / joi)."),
        "en": ("NoSQL injection", "", ""),
    },
    "ARX-CMDI": {
        "uz": ("OS buyruq in'ektsiyasi",
               "Shell buyrug'i kiritilgan qiymatdan yig'ilgan — `; rm -rf /` kabi qo'shimcha bilan serverda istalgan buyruqni bajarish mumkin.",
               'Shell\'siz chaqiring: execFile("ping", ["-c", "1", host]) / subprocess.run([...]) va qiymatni allow-list bilan tekshiring.'),
        "ru": ("Инъекция команд ОС",
               "Команда оболочки собирается из ввода — добавкой вида `; rm -rf /` можно выполнить любую команду на сервере.",
               'Вызывайте без shell: execFile("ping", ["-c", "1", host]) / subprocess.run([...]) и проверяйте значение по allow-list.'),
        "en": ("OS command injection", "", ""),
    },
    "ARX-EVAL": {
        "uz": ("eval orqali kod in'ektsiyasi",
               "Satr kod sifatida bajarilyapti — hujumchi serverda o'z kodini ishga tushiradi (RCE).",
               "Satrni kod sifatida bajarmang: ma'lumot uchun JSON.parse / ast.literal_eval, amallar uchun ruxsat etilgan funksiyalar xaritasi."),
        "ru": ("Инъекция кода через eval",
               "Строка выполняется как код — атакующий запускает свой код на сервере (RCE).",
               "Не выполняйте строки как код: для данных — JSON.parse / ast.literal_eval, для действий — карта разрешённых функций."),
        "en": ("Code injection via eval", "", ""),
    },
    "ARX-SSTI": {
        "uz": ("Server tomonidagi shablon in'ektsiyasi",
               "Shablon kiritilgan qiymatdan kompilyatsiya qilinyapti — {{ }} ichidagi ifoda orqali serverda kod bajariladi.",
               "Shablonlarni fayllarda saqlang (render_template), foydalanuvchi ma'lumotini faqat o'zgaruvchi sifatida uzating."),
        "ru": ("Инъекция шаблонов (SSTI)",
               "Шаблон компилируется из ввода — выражение в {{ }} выполняет код на сервере.",
               "Храните шаблоны в файлах (render_template), пользовательские данные передавайте только как переменные."),
        "en": ("Server-side template injection", "", ""),
    },
    "ARX-XSS": {
        "uz": ("Saytlararo skripting (XSS)",
               "Kiritilgan qiymat HTML'ga ekranlanmasdan qo'shilyapti — hujumchi foydalanuvchilar brauzerida JavaScript ishga tushirib, sessiyani o'g'irlaydi.",
               "JSON qaytaring yoki qiymatni ekranlang; DOM'da textContent yoki DOMPurify.sanitize() ishlating."),
        "ru": ("Межсайтовый скриптинг (XSS)",
               "Ввод вставляется в HTML без экранирования — атакующий запускает JavaScript в браузере пользователей и крадёт сессию.",
               "Возвращайте JSON или экранируйте значение; в DOM используйте textContent или DOMPurify.sanitize()."),
        "en": ("Cross-site scripting (XSS)", "", ""),
    },
    "ARX-PATH": {
        "uz": ("Path traversal (papkadan chiqib ketish)",
               "Fayl yo'li kiritilgan qiymatdan yig'ilgan — `../../etc/passwd` bilan serverdagi istalgan faylni o'qish yoki ustiga yozish mumkin.",
               "Yo'lni path.resolve bilan hisoblang va ruxsat etilgan papka ichida ekanini startsWith bilan tekshiring yoki path.basename / secure_filename ishlating."),
        "ru": ("Обход каталога (path traversal)",
               "Путь к файлу собирается из ввода — через `../../etc/passwd` можно прочитать или перезаписать любой файл на сервере.",
               "Вычисляйте путь через path.resolve и проверяйте startsWith разрешённой папки, либо используйте path.basename / secure_filename."),
        "en": ("Path traversal", "", ""),
    },
    "ARX-SSRF": {
        "uz": ("Server tomonidan so'rov soxtalashtirish (SSRF)",
               "Server foydalanuvchi bergan URL'ga so'rov yuboryapti — ichki xizmatlar va bulut metadata'siga (169.254.169.254) kirish mumkin.",
               "Host'ni allow-list bilan tekshiring va xususiy IP diapazonlarini bloklang."),
        "ru": ("Подделка серверных запросов (SSRF)",
               "Сервер делает запрос по URL пользователя — доступ к внутренним сервисам и метаданным облака (169.254.169.254).",
               "Проверяйте хост по allow-list и блокируйте приватные диапазоны IP."),
        "en": ("Server-side request forgery (SSRF)", "", ""),
    },
    "ARX-REDIRECT": {
        "uz": ("Ochiq yo'naltirish (open redirect)",
               "Yo'naltirish manzili so'rovdan olinyapti — hujumchi sizning domeningiz orqali qurbonni fishing saytiga yuboradi.",
               "Faqat nisbiy yo'llarga yoki ruxsat etilgan URL ro'yxatiga yo'naltiring."),
        "ru": ("Открытый редирект",
               "Адрес перенаправления берётся из запроса — атакующий отправляет жертву на фишинговый сайт через ваш домен.",
               "Перенаправляйте только на относительные пути или по разрешённому списку URL."),
        "en": ("Open redirect", "", ""),
    },
    "ARX-DESER": {
        "uz": ("Xavfli deserializatsiya",
               "pickle / yaml.load / node-serialize ma'lumotni yuklayotganda kod bajaradi — ishonchsiz ma'lumot masofaviy kod bajarilishiga (RCE) olib keladi.",
               "Ishonchsiz ma'lumot uchun JSON ishlating; YAML uchun yaml.safe_load."),
        "ru": ("Небезопасная десериализация",
               "pickle / yaml.load / node-serialize выполняют код при загрузке — недоверенные данные ведут к удалённому выполнению кода (RCE).",
               "Для недоверенных данных используйте JSON; для YAML — yaml.safe_load."),
        "en": ("Unsafe deserialization", "", ""),
    },
    "ARX-SECRET": {
        "uz": ("Kodda qolgan maxfiy kalit",
               "API kalit, parol yoki shaxsiy kalit repozitoriyga yozilgan — repoga (yoki git tarixiga) kira olgan har kim undan foydalana oladi.",
               "Kalitni muhit o'zgaruvchisidan o'qing, faylni .gitignore'ga qo'shing va kalitni almashtiring — u git tarixida qolgan."),
        "ru": ("Секрет в коде",
               "API-ключ, пароль или приватный ключ записан в репозиторий — любой с доступом к репозиторию (или git-истории) может им воспользоваться.",
               "Читайте ключ из переменной окружения, добавьте файл в .gitignore и перевыпустите ключ — он уже в git-истории."),
        "en": ("Hard-coded secret", "", ""),
    },
    "ARX-JWT": {
        "uz": ("JWT imzosi tekshirilmayapti",
               "Token imzosi tekshirilmasdan qabul qilinyapti (alg: none) — istalgan kishi o'zini admin qilib token yasay oladi.",
               "Aniq algoritm ro'yxati bilan tekshiring: jwt.verify(token, key, { algorithms: ['HS256'] })."),
        "ru": ("Подпись JWT не проверяется",
               "Токен принимается без проверки подписи (alg: none) — любой может подделать токен администратора.",
               "Проверяйте с явным списком алгоритмов: jwt.verify(token, key, { algorithms: ['HS256'] })."),
        "en": ("JWT signature not verified", "", ""),
    },
    "ARX-CORS": {
        "uz": ("Cookie bilan ochiq CORS",
               "Istalgan sayt foydalanuvchi cookie'lari bilan so'rov yubora oladi — tizimga kirgan foydalanuvchi nomidan amallar bajariladi.",
               "Ruxsat etilgan origin'larni aniq sanab o'ting; wildcard yoki qaytarilgan origin'ni credentials bilan birga ishlatmang."),
        "ru": ("Открытый CORS с cookie",
               "Любой сайт может отправлять запросы с cookie пользователя — действия от имени вошедшего пользователя.",
               "Перечисляйте разрешённые origin явно; не сочетайте wildcard или отражённый origin с credentials."),
        "en": ("Permissive CORS with credentials", "", ""),
    },
    "ARX-TLS": {
        "uz": ("TLS sertifikat tekshiruvi o'chirilgan",
               "HTTPS sertifikati tekshirilmayapti — tarmoqdagi hujumchi trafikni o'qiydi va o'zgartiradi (MITM).",
               "Sertifikat tekshiruvini yoqilgan holda qoldiring; ichki xizmatlar uchun o'z CA faylingizni bering."),
        "ru": ("Проверка TLS-сертификата отключена",
               "Сертификат HTTPS не проверяется — атакующий в сети читает и изменяет трафик (MITM).",
               "Оставьте проверку включённой; для внутренних сервисов укажите свой CA."),
        "en": ("TLS certificate verification disabled", "", ""),
    },
    "ARX-DEBUG": {
        "uz": ("Debug rejimi yoqilgan",
               "Debug rejimi stack trace va sozlamalarni ko'rsatadi, Flask/Werkzeug'da esa masofaviy Python konsolini ochadi.",
               "Debug'ni muhit o'zgaruvchisidan o'qing va production'da o'chiq saqlang."),
        "ru": ("Включён режим отладки",
               "Режим отладки раскрывает стек вызовов и настройки, а во Flask/Werkzeug открывает удалённую консоль Python.",
               "Читайте debug из переменной окружения и выключайте его в production."),
        "en": ("Debug mode enabled", "", ""),
    },
    "ARX-WEAKHASH": {
        "uz": ("Zaif hash algoritmi",
               "MD5 / SHA-1 da kolliziyalar amalda topiladi — parol, imzo va tokenlar uchun yaroqsiz.",
               "Parollar uchun bcrypt / argon2, butunlik uchun SHA-256+ (HMAC-SHA-256) ishlating."),
        "ru": ("Слабый алгоритм хеширования",
               "Для MD5 / SHA-1 коллизии находятся на практике — не подходят для паролей, подписей и токенов.",
               "Для паролей — bcrypt / argon2, для целостности — SHA-256+ (HMAC-SHA-256)."),
        "en": ("Weak hash algorithm", "", ""),
    },
}

# Deep-scan findings (git history, project-level checks, AI review).
RULES.update({
    "ARX-SECRET-HISTORY": {
        "uz": ("Git tarixida qolgan kalit", "Bu kalit fayldan o'chirilgan, lekin eski commit'da hali ham bor — repoga kirgan har kim uni tarixdan topa oladi.",
               "Kalitni darhol almashtiring, keyin git filter-repo / BFG bilan tarixdan o'chirib, force-push qiling."),
        "ru": ("Секрет в истории git", "Ключ удалён из файла, но остался в старом коммите — любой с доступом к репозиторию найдёт его в истории.",
               "Сразу перевыпустите ключ, затем удалите его из истории (git filter-repo / BFG) и сделайте force-push."),
        "en": ("Secret in git history", "", ""),
    },
    "ARX-NOAUTH": {
        "uz": ("Loyihada autentifikatsiya yo'q", "Hech bir so'rov handler'ida sessiya, JWT yoki login tekshiruvi topilmadi — barcha endpoint'lar hamma uchun ochiq.",
               "Autentifikatsiya qatlamini (sessiya / JWT middleware) qo'shing va uni har bir yopiq route'ga qo'llang."),
        "ru": ("В проекте нет аутентификации", "Ни в одном обработчике запросов нет сессии, JWT или проверки входа — все эндпоинты открыты для всех.",
               "Добавьте слой аутентификации (сессии / JWT middleware) и примените его ко всем закрытым маршрутам."),
        "en": ("No authentication in the project", "", ""),
    },
    "ARX-IDOR": {
        "uz": ("IDOR ehtimoli (egalik tekshiruvi yo'q)", "Yozuv so'rovdan kelgan id bo'yicha yuklanyapti, lekin joriy foydalanuvchiga tegishliligi tekshirilmaydi — id'ni o'zgartirib, boshqalarning ma'lumotini ko'rish mumkin.",
               "Yozuvni id VA joriy foydalanuvchi id'si bo'yicha yuklang yoki qaytarishdan oldin egasini tekshiring."),
        "ru": ("Возможный IDOR (нет проверки владельца)", "Запись загружается по id из запроса, но принадлежность текущему пользователю не проверяется — сменив id, можно читать чужие данные.",
               "Загружайте запись по id И id текущего пользователя или проверяйте владельца перед ответом."),
        "en": ("Possible IDOR (missing ownership check)", "", ""),
    },
})
_AI = {
    "MISSING-AUTH": (("Muhim amalda autentifikatsiya yo'q", "Bu handler foydalanuvchi tizimga kirganini tekshirmasdan muhim amalni bajaryapti."),
                     ("Нет аутентификации на важном действии", "Обработчик выполняет важное действие без проверки входа пользователя.")),
    "BROKEN-ACCESS": (("Egalik tekshiruvi yo'q (IDOR)", "Ma'lumot kimga tegishli ekani tekshirilmasdan qaytarilyapti yoki o'zgartirilyapti."),
                      ("Нет проверки владельца (IDOR)", "Данные возвращаются или меняются без проверки, кому они принадлежат.")),
    "MASS-ASSIGNMENT": (("So'rov maydonlarini ommaviy yozish", "So'rov tanasi to'liq holda modelga yozilyapti — hujumchi role yoki isAdmin kabi maydonni ham o'zgartira oladi."),
                        ("Массовое присвоение полей", "Тело запроса целиком записывается в модель — атакующий может изменить поля вроде role или isAdmin.")),
    "DATA-EXPOSURE": (("Maxfiy ma'lumot mijozga qaytarilyapti", "Javobda parol hash'i, token yoki ichki ma'lumot bo'lishi mumkin."),
                      ("Раскрытие чувствительных данных", "Ответ может содержать хеш пароля, токен или внутренние данные.")),
    "BRUTE-FORCE": (("Brute-force himoyasi yo'q", "Login yoki parolni tiklash endpoint'ida urinishlar soni cheklanmagan."),
                    ("Нет защиты от перебора", "На входе или сбросе пароля не ограничено число попыток.")),
    "LOGIC": (("Biznes-mantiq xatosi", "Server tomonida biznes qoidasi to'liq tekshirilmayapti."),
              ("Ошибка бизнес-логики", "Бизнес-правило не проверяется полностью на стороне сервера.")),
}
_AI_NOTE = {"uz": " (AI tahlili — tasdiqlanmagan, qo'lda tekshiring)", "ru": " (анализ ИИ — не подтверждено, проверьте вручную)"}
for _kind, ((uz_t, uz_w), (ru_t, ru_w)) in _AI.items():
    RULES[f"ARX-AI-{_kind}"] = {"uz": (uz_t, uz_w + _AI_NOTE["uz"], ""), "ru": (ru_t, ru_w + _AI_NOTE["ru"], ""), "en": ("", "", "")}


DEP = {
    "uz": {"title": "Zaif kutubxona", "mal_title": "Zararli paket",
           "msg": "{pkg}@{ver}: {n} ta ma'lum zaiflik ({ids}) — {summary}",
           "mal_msg": "{pkg}@{ver} — ma'lum ZARARLI paket ({id}). {summary}",
           "fix": "{pkg} ni {target} yoki yangiroq versiyaga yangilang.",
           "nofix": "Tuzatilgan versiya hali yo'q — {pkg} ni almashtiring yoki ishlatilishini cheklang.",
           "mal_fix": "{pkg} ni darhol o'chiring, toza lockfile'dan qayta o'rnating va u o'rnatilgan kompyuterlardagi kalitlarni almashtiring."},
    "ru": {"title": "Уязвимая зависимость", "mal_title": "Вредоносный пакет",
           "msg": "{pkg}@{ver}: известных уязвимостей — {n} ({ids}) — {summary}",
           "mal_msg": "{pkg}@{ver} — известный ВРЕДОНОСНЫЙ пакет ({id}). {summary}",
           "fix": "Обновите {pkg} до {target} или новее.",
           "nofix": "Исправленной версии пока нет — замените {pkg} или ограничьте его использование.",
           "mal_fix": "Немедленно удалите {pkg}, переустановите из чистого lockfile и перевыпустите секреты на машинах, где он был установлен."},
}

UI = {
    "uz": {"target": "loyiha", "files": "fayllar", "lines": "qator", "rules": "qoida", "deps": "paketlar",
           "deps_ok": "{n} ta paket oflayn OSV bazasi bo'yicha tekshirildi", "deps_off": "o'tkazib yuborildi — paket CVE'lari uchun bir marta [bold]armorix db update[/] ni ishga tushiring",
           "tagline": "lokal statik tahlil", "network": "tarmoq: o'chiq", "fix": "tuzatish", "source": "manba", "flows": "oqim", "sink": "sink",
           "summary": "xulosa", "clean": "✓ muammo topilmadi", "issues": "{n} ta muammo", "time": "{ms} ms da skanerlandi",
           "zero": "tarmoqqa 0 bayt yuborildi", "from": "Manba: `{src}`.",
           "report": "Xavfsizlik hisoboti", "filter": "Fayl, qoida yoki matn bo'yicha filtrlash…", "offline": "oflayn · 0 bayt yuborildi",
           "footer": "Armorix v{v} tomonidan lokal yaratildi — AST-asosidagi statik kod tahlili, ma'lumot bu kompyuterdan chiqmadi.",
           "none": "Muammo topilmadi.", "verified": "✓ tekshirildi", "rejected": "✗ rad etildi", "passed": "ta patch tekshiruvdan o'tdi",
           "applied": "{n} ta patch qo'llandi", "writing": "lokal model patch yozmoqda…", "skipped": "o'tkazildi",
           "skipped_cfg": "konfiguratsiya qiymati — uni fayldan o'chiring va kalitni almashtiring",
           "dry": "sinov rejimi — yozish uchun [bold]--apply[/] qo'shing (zaxira: *.armorix.bak)", "to_patch": "{n} ta topilma (≥ {sev}) tuzatiladi — har bir patch qayta tahlil qilinadi",
           "localhost": "tarmoq: faqat localhost"},
    "ru": {"target": "проект", "files": "файлы", "lines": "строк", "rules": "правил", "deps": "пакеты",
           "deps_ok": "{n} пакетов проверено по офлайн-базе OSV", "deps_off": "пропущено — один раз запустите [bold]armorix db update[/] для проверки CVE пакетов",
           "tagline": "локальный статический анализ", "network": "сеть: выкл", "fix": "исправление", "source": "источник", "flows": "поток", "sink": "сток",
           "summary": "итог", "clean": "✓ проблем не найдено", "issues": "проблем: {n}", "time": "просканировано за {ms} мс",
           "zero": "в сеть отправлено 0 байт", "from": "Источник: `{src}`.",
           "report": "Отчёт по безопасности кода", "filter": "Фильтр по файлу, правилу или тексту…", "offline": "офлайн · отправлено 0 байт",
           "footer": "Создано локально Armorix v{v} — статический анализ на основе AST, данные не покидали этот компьютер.",
           "none": "Проблем не найдено.", "verified": "✓ проверено", "rejected": "✗ отклонено", "passed": "патчей прошли проверку",
           "applied": "применено патчей: {n}", "writing": "локальная модель пишет патч…", "skipped": "пропущено",
           "skipped_cfg": "значение конфигурации — удалите его из файла и перевыпустите секрет",
           "dry": "пробный режим — добавьте [bold]--apply[/] для записи (резервные копии: *.armorix.bak)", "to_patch": "находок для исправления (≥ {sev}): {n} — каждый патч проверяется повторным сканированием",
           "localhost": "сеть: только localhost"},
    "en": {"target": "target", "files": "files", "lines": "lines", "rules": "rules", "deps": "deps",
           "deps_ok": "{n} packages checked against the offline OSV database", "deps_off": "skipped — run [bold]armorix db update[/] once to enable dependency CVE checks",
           "tagline": "local static analysis", "network": "network: off", "fix": "fix", "source": "source", "flows": "flows", "sink": "sink",
           "summary": "summary", "clean": "✓ no issues found", "issues": "{n} issue(s)", "time": "scanned in {ms} ms",
           "zero": "0 bytes sent over the network", "from": "",
           "report": "Security report", "filter": "Filter by file, rule or text…", "offline": "offline · 0 bytes sent",
           "footer": "Generated locally by Armorix v{v} — AST-based static analysis, no data left this machine.",
           "none": "No issues found.", "verified": "✓ verified", "rejected": "✗ rejected", "passed": "patches passed verification",
           "applied": "applied {n} patch(es)", "writing": "local model is writing a patch…", "skipped": "skipped",
           "skipped_cfg": "config value — remove it from the file and rotate the secret",
           "dry": "dry run — add [bold]--apply[/] to write them (backups: *.armorix.bak)", "to_patch": "{n} finding(s) ≥ {sev} to patch — each patch is re-parsed and re-scanned before it counts",
           "localhost": "network: localhost only"},
}

SEVERITY = {
    "uz": {Severity.CRITICAL: "KRITIK", Severity.HIGH: "YUQORI", Severity.MEDIUM: "O'RTA", Severity.LOW: "PAST"},
    "ru": {Severity.CRITICAL: "КРИТИЧНО", Severity.HIGH: "ВЫСОКИЙ", Severity.MEDIUM: "СРЕДНИЙ", Severity.LOW: "НИЗКИЙ"},
    "en": {s: s.name for s in Severity},
}


def detect(explicit: str | None = None) -> str:
    if explicit in LANGS:
        return explicit
    env = (os.environ.get("ARMORIX_LANG") or os.environ.get("LANG") or "en")[:2].lower()
    return env if env in LANGS else "en"


def ui(lang: str, key: str, **kw) -> str:
    return UI[lang][key].format(**kw)


def severity(lang: str, sev: Severity) -> str:
    return SEVERITY[lang][sev]


def localize(f: Finding, lang: str) -> tuple[str, str, str]:
    """(title, message, fix) for display. English keeps the rule's own, more specific wording."""
    if lang == "en":
        return f.title, f.message, f.fix
    if f.rule_id == "ARX-DEP" and f.data:
        d, t = f.data, DEP[lang]
        if d.get("malicious"):
            return t["mal_title"], t["mal_msg"].format(**d), t["mal_fix"].format(**d)
        fix = t["fix"].format(**d) if d.get("target") else t["nofix"].format(**d)
        return t["title"], t["msg"].format(**d), fix
    title, why, fix = RULES.get(f.rule_id, {}).get(lang, (f.title, f.message, f.fix))
    fix = fix or f.fix  # AI-review fixes are generic English templates when no translation exists
    if f.data.get("source"):
        why = f"{why} {ui(lang, 'from', src=f.data['source'])}"
    return title, why, fix
