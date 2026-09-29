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


# C / C++ memory safety.
RULES.update({
    "ARX-C-BOF": {
        "uz": ("Bufer to'lishi (buffer overflow)", "Ma'lumot qat'iy o'lchamli buferga uzunligi tekshirilmasdan nusxalanyapti — stek yoki heap ustiga yozilib, dasturni boshqarib olish mumkin.",
               "Har bir nusxani manzil o'lchami bilan cheklang: snprintf(buf, sizeof(buf), \"%s\", src) yoki strlcpy; kiruvchi uzunlikni oldindan tekshiring."),
        "ru": ("Переполнение буфера", "Данные копируются в буфер фиксированного размера без проверки длины — перезапись стека или кучи и захват управления программой.",
               "Ограничивайте каждое копирование размером приёмника: snprintf(buf, sizeof(buf), \"%s\", src) или strlcpy; проверяйте длину входа заранее."),
        "en": ("Buffer overflow", "", ""),
    },
    "ARX-C-GETS": {
        "uz": ("Tabiatan xavfli funksiya (gets)", "gets() qatorni cheksiz o'qiydi — har bir chaqiruv bufer to'lishiga olib kelishi mumkin.",
               "gets() ni fgets(buf, sizeof(buf), stdin) bilan almashtiring."),
        "ru": ("Опасная по своей природе функция (gets)", "gets() читает строку без ограничения длины — каждый вызов может переполнить буфер.",
               "Замените gets() на fgets(buf, sizeof(buf), stdin)."),
        "en": ("Inherently dangerous function", "", ""),
    },
    "ARX-C-UAF": {
        "uz": ("Bo'shatilgan xotiradan foydalanish (use-after-free)", "Xotira free/delete qilingandan keyin unga yana murojaat qilinyapti — hujumchi o'sha joyga o'z ma'lumotini joylab, dasturni boshqarishi mumkin.",
               "free/delete'dan keyin xotiraga tegmang: foydalanishni undan oldinga ko'chiring va ko'rsatkichni NULL / nullptr qiling."),
        "ru": ("Использование после освобождения (use-after-free)", "К памяти обращаются после free/delete — атакующий может подложить туда свои данные и перехватить управление.",
               "Не трогайте память после free/delete: перенесите использование до освобождения и обнулите указатель (NULL / nullptr)."),
        "en": ("Use after free", "", ""),
    },
    "ARX-C-DFREE": {
        "uz": ("Ikki marta bo'shatish (double free)", "Bitta xotira ikki marta bo'shatilyapti — heap buziladi, bu ko'pincha kod bajarilishiga olib keladi.",
               "free'dan keyin ko'rsatkichni NULL qiling — ikkinchi free zararsiz bo'ladi; xotira egaligini bitta joyda saqlang."),
        "ru": ("Двойное освобождение (double free)", "Одна и та же память освобождается дважды — куча повреждается, что часто ведёт к выполнению кода.",
               "Обнуляйте указатель после free — повторный free станет безвредным; держите владение памятью в одном месте."),
        "en": ("Double free", "", ""),
    },
    "ARX-C-FMT": {
        "uz": ("Format satri zaifligi", "Format satri o'zgaruvchidan olinmoqda — kiritilgan %n / %x orqali xotirani o'qish yoki yozish mumkin.",
               "Doimiy format satridan foydalaning: printf(msg) emas, printf(\"%s\", msg)."),
        "ru": ("Уязвимость форматной строки", "Форматная строка берётся из переменной — через %n / %x во входе можно читать или писать память.",
               "Используйте постоянную форматную строку: printf(\"%s\", msg) вместо printf(msg)."),
        "en": ("Format string vulnerability", "", ""),
    },
    "ARX-C-INTOVF": {
        "uz": ("Xotira ajratishda butun son to'lishi", "Ajratiladigan hajm tekshirilmagan kiruvchi qiymatdan ko'paytirib hisoblanyapti — natija \"o'ralib\" ketsa, juda kichik bufer ajratiladi.",
               "Ko'paytirishni to'lishga tekshiring (yoki calloc / reallocarray ishlating)."),
        "ru": ("Целочисленное переполнение при выделении памяти", "Размер выделения вычисляется умножением непроверенного входного значения — при переполнении выделяется слишком маленький буфер.",
               "Проверяйте умножение на переполнение (или используйте calloc / reallocarray)."),
        "en": ("Integer overflow in allocation size", "", ""),
    },
    "ARX-C-CMDI": {
        "uz": ("OS buyruq in'ektsiyasi", "system()/popen() kiritilgan qiymatdan yig'ilgan buyruqni bajaryapti — hujumchi istalgan buyruqni ishga tushiradi.",
               "system()/popen() o'rniga argumentlar massivi bilan execve chaqiring va har bir qiymatni allow-list bilan tekshiring."),
        "ru": ("Инъекция команд ОС", "system()/popen() выполняют команду, собранную из ввода, — атакующий запускает любую команду.",
               "Вместо system()/popen() вызывайте execve с массивом аргументов и проверяйте значения по allow-list."),
        "en": ("OS command injection", "", ""),
    },
})


# Application logic, CI and infrastructure (v0.3).
RULES.update({
    "ARX-MASS": {
        "uz": ("Ommaviy yozish (mass assignment)", "So'rov tanasi to'liqligicha modelga yozilyapti — foydalanuvchi isAdmin, role yoki balance kabi maydonni ham o'zgartira oladi.",
               "Faqat ruxsat etilgan maydonlarni ko'chiring (allow-list yoki zod / pydantic sxemasi) va keyin saqlang."),
        "ru": ("Массовое присвоение (mass assignment)", "Тело запроса целиком записывается в модель — пользователь может изменить поля вроде isAdmin, role или balance.",
               "Копируйте только разрешённые поля (allow-list или схема zod / pydantic) и только потом сохраняйте."),
        "en": ("Mass assignment", "", ""),
    },
    "ARX-PROTO": {
        "uz": ("Prototype pollution", "Ishonchsiz kalitlar obyektlarga birlashtirilyapti — `__proto__` kaliti jarayondagi barcha obyektlarni o'zgartiradi (auth chetlab o'tish, RCE).",
               "Faqat ma'lum kalitlarni birlashtiring (yoki Object.create(null) / Map), __proto__ / constructor / prototype ni rad eting, lodash ≥ 4.17.21."),
        "ru": ("Загрязнение прототипа", "Непроверенные ключи сливаются в объекты — ключ `__proto__` меняет все объекты процесса (обход авторизации, RCE).",
               "Сливайте только известные ключи (или Object.create(null) / Map), отклоняйте __proto__ / constructor / prototype, lodash ≥ 4.17.21."),
        "en": ("Prototype pollution", "", ""),
    },
    "ARX-REGEX": {
        "uz": ("Regex in'ektsiyasi (ReDoS)", "Regulyar ifoda foydalanuvchi kiritgan qiymatdan tuziladi — (a+)+$ kabi naqsh serverni muzlatib qo'yadi.",
               "Qiymatni ekranlang (_.escapeRegExp / re.escape) yoki oddiy matn sifatida solishtiring (includes / in)."),
        "ru": ("Инъекция регулярного выражения (ReDoS)", "Регулярное выражение строится из ввода — шаблон вида (a+)+$ подвешивает сервер.",
               "Экранируйте значение (_.escapeRegExp / re.escape) или сравнивайте как обычный текст (includes / in)."),
        "en": ("Regular expression injection (ReDoS)", "", ""),
    },
    "ARX-COOKIE": {
        "uz": ("Sessiya cookie'sida HttpOnly / Secure yo'q", "Sessiya yoki token cookie'sini JavaScript o'qiy oladi (XSS orqali o'g'irlanadi) yoki u shifrlanmagan HTTP orqali yuboriladi.",
               "Sessiya va token cookie'lariga httpOnly: true, secure: true va sameSite: 'lax' qo'ying."),
        "ru": ("Cookie сессии без HttpOnly / Secure", "Cookie сессии или токена доступна JavaScript (крадётся через XSS) или уходит по незашифрованному HTTP.",
               "Ставьте httpOnly: true, secure: true и sameSite: 'lax' на cookie сессий и токенов."),
        "en": ("Session cookie without HttpOnly / Secure", "", ""),
    },
    "ARX-RANDOM": {
        "uz": ("Maxfiy qiymat uchun oldindan aytib bo'ladigan tasodifiy son", "Token, parol yoki kod kriptografik bo'lmagan generator (Math.random / random) bilan yaratilyapti — keyingi qiymatlarni taxmin qilish mumkin.",
               "crypto.randomBytes / crypto.randomUUID yoki Python'da secrets.token_urlsafe() ishlating."),
        "ru": ("Предсказуемое случайное значение для секрета", "Токен, пароль или код создаётся некриптографическим генератором (Math.random / random) — следующие значения можно предсказать.",
               "Используйте crypto.randomBytes / crypto.randomUUID или secrets.token_urlsafe() в Python."),
        "en": ("Predictable random value for a secret", "", ""),
    },
    "ARX-SIGNKEY": {
        "uz": ("Imzo kaliti kod ichida", "JWT yoki sessiya cookie'lari kod ichiga yozilgan kalit bilan imzolanyapti — kodni ko'rgan har kim istalgan foydalanuvchi nomidan kira oladi.",
               "Kalitni muhit o'zgaruvchisi yoki secret store'dan o'qing (process.env.JWT_SECRET / os.environ['SECRET_KEY']) va uni almashtiring."),
        "ru": ("Ключ подписи в коде", "JWT или cookie сессии подписываются ключом, записанным в коде, — любой, кто видел код, может войти от имени любого пользователя.",
               "Читайте ключ из переменной окружения или хранилища секретов (process.env.JWT_SECRET / os.environ['SECRET_KEY']) и перевыпустите его."),
        "en": ("Hard-coded signing key", "", ""),
    },
    "ARX-XXE": {
        "uz": ("XML tashqi entity (XXE)", "XML parser tashqi entity'larni ochyapti — yuklangan XML serverdagi fayllarni o'qishi yoki ichki URL'larga murojaat qilishi mumkin.",
               "defusedxml ishlating yoki entity'larni o'chiring: lxml XMLParser(resolve_entities=False), libxmljs'da noent: true bermang."),
        "ru": ("Внешние сущности XML (XXE)", "XML-парсер раскрывает внешние сущности — загруженный XML может читать файлы сервера или обращаться к внутренним URL.",
               "Используйте defusedxml или отключите сущности: lxml XMLParser(resolve_entities=False), в libxmljs не передавайте noent: true."),
        "en": ("XML external entities (XXE)", "", ""),
    },
    "ARX-AUTOESCAPE": {
        "uz": ("Shablonda avtomatik ekranlash o'chirilgan", "HTML shablonlar o'zgaruvchilarni ekranlamasdan chiqaryapti — har qanday foydalanuvchi qiymati XSS'ga aylanadi.",
               "Avtomatik ekranlashni yoqilgan holda qoldiring va faqat tozalangan, ishonchli HTML'ni safe deb belgilang."),
        "ru": ("Автоэкранирование в шаблонах отключено", "HTML-шаблоны выводят переменные без экранирования — любое пользовательское значение становится XSS.",
               "Оставьте автоэкранирование включённым и помечайте как safe только очищенный, доверенный HTML."),
        "en": ("Template auto-escaping disabled", "", ""),
    },
    "ARX-CSRF": {
        "uz": ("CSRF himoyasi o'chirilgan", "Holatni o'zgartiradigan view istalgan saytdan kelgan so'rovni qabul qiladi — zararli sahifa foydalanuvchi nomidan amal bajaradi.",
               "@csrf_exempt ni olib tashlang; API uchun cookie o'rniga token (Authorization sarlavhasi) ishlating."),
        "ru": ("Защита от CSRF отключена", "Изменяющий состояние обработчик принимает запросы с любого сайта — вредоносная страница действует от имени пользователя.",
               "Уберите @csrf_exempt; для API используйте токен (заголовок Authorization) вместо cookie."),
        "en": ("CSRF protection disabled", "", ""),
    },
    "ARX-PERMS": {
        "uz": ("Hamma yoza oladigan fayl huquqlari", "Faylga kompyuterdagi har bir foydalanuvchi yoza oladigan qilinyapti (777 / 666).",
               "Eng tor huquqni bering: maxfiy fayllar uchun 0o600, ochiq fayllar uchun 0o644, dasturlar uchun 0o755."),
        "ru": ("Права на запись для всех", "Файл делается доступным для записи любому пользователю системы (777 / 666).",
               "Давайте минимальные права: 0o600 для секретов, 0o644 для публичных файлов, 0o755 для программ."),
        "en": ("World-writable file permissions", "", ""),
    },
    "ARX-TMPFILE": {
        "uz": ("Xavfli vaqtinchalik fayl", "tempfile.mktemp() faqat nom qaytaradi — boshqa jarayon faylni birinchi bo'lib yaratib olishi mumkin.",
               "tempfile.NamedTemporaryFile() yoki tempfile.mkstemp() ishlating."),
        "ru": ("Небезопасный временный файл", "tempfile.mktemp() возвращает только имя — другой процесс может создать файл первым.",
               "Используйте tempfile.NamedTemporaryFile() или tempfile.mkstemp()."),
        "en": ("Insecure temporary file", "", ""),
    },
    "ARX-GHA-INJECT": {
        "uz": ("GitHub Actions skript in'ektsiyasi", "Issue sarlavhasi, PR branch nomi yoki commit xabari to'g'ridan-to'g'ri shell qadamiga qo'yilyapti — istalgan odam CI'da buyruq bajarib, token va secret'larni o'g'irlaydi.",
               "Qiymatni env orqali uzating (env: TITLE: ${{ github.event.issue.title }}) va skriptda \"$TITLE\" ishlating — run: ichida ${{ … }} qo'ymang."),
        "ru": ("Инъекция в скрипт GitHub Actions", "Заголовок issue, имя ветки PR или сообщение коммита вставляются прямо в shell-шаг — любой может выполнить команды в CI и украсть токен и секреты.",
               "Передавайте значение через env (env: TITLE: ${{ github.event.issue.title }}) и используйте \"$TITLE\" — не пишите ${{ … }} внутри run:."),
        "en": ("GitHub Actions script injection", "", ""),
    },
    "ARX-GHA-PWN": {
        "uz": ("Ishonchsiz PR kodi secret'lar bilan ishga tushadi (pwn request)", "pull_request_target / workflow_run ishi tashqi ishtirokchi kodini checkout qilib, yozish huquqi va secret'lar bilan bajaryapti.",
               "Ishonchsiz kodni qurish uchun on: pull_request ishlating yoki pull_request_target'da PR head'ini checkout qilmang."),
        "ru": ("Недоверенный код PR запускается с секретами (pwn request)", "Задание pull_request_target / workflow_run делает checkout кода внешнего участника и запускает его с правами записи и секретами.",
               "Для сборки недоверенного кода используйте on: pull_request или не делайте checkout head PR в pull_request_target."),
        "en": ("Untrusted pull request code runs with secrets (pwn request)", "", ""),
    },
    "ARX-DOCKER": {
        "uz": ("Xavfli Dockerfile ko'rsatmasi", "Konteyner root sifatida ishlaydi, secret image qatlamlariga yozilgan yoki yuklab olingan skript to'g'ridan-to'g'ri shell'ga uzatilyapti.",
               "USER bilan oddiy foydalanuvchiga o'ting, secret'larni ishga tushirishda bering (BuildKit --mount=type=secret), yuklamalarni sha256 bilan tekshiring, image versiyasini qotiring."),
        "ru": ("Опасная инструкция Dockerfile", "Контейнер работает от root, секрет записан в слои образа или скачанный скрипт сразу передаётся в shell.",
               "Переключитесь на обычного пользователя через USER, передавайте секреты при запуске (BuildKit --mount=type=secret), проверяйте загрузки по sha256, фиксируйте версию образа."),
        "en": ("Risky Dockerfile instruction", "", ""),
    },
    "ARX-CONTAINER": {
        "uz": ("Ortiqcha huquqli konteyner", "Konteyner privileged rejimda, host tarmog'i / PID'ini bo'lishadi yoki Docker socket ulangan — undan chiqib ketish host'da root beradi.",
               "privileged va host namespace'larni o'chiring, /var/run/docker.sock ni ulamang, konteynerni minimal huquqli oddiy foydalanuvchi bilan ishga tushiring."),
        "ru": ("Контейнер с избыточными правами", "Контейнер запущен в privileged-режиме, делит сеть / PID хоста или смонтирован Docker socket — побег из него даёт root на хосте.",
               "Отключите privileged и общие namespace хоста, не монтируйте /var/run/docker.sock, запускайте от непривилегированного пользователя с минимумом прав."),
        "en": ("Over-privileged container", "", ""),
    },
    "ARX-TF": {
        "uz": ("Bulut resursi internetga ochiq", "Terraform bucket, ma'lumotlar bazasi yoki admin portni butun internetga ochyapti.",
               "Kirishni ma'lum CIDR / security group'lar bilan cheklang, bucket'larni yopiq, bazalarni xususiy subnet'da saqlang."),
        "ru": ("Облачный ресурс открыт в интернет", "Terraform открывает bucket, базу данных или административный порт всему интернету.",
               "Ограничьте доступ известными CIDR / security group, держите bucket закрытыми, а базы — в приватных подсетях."),
        "en": ("Publicly exposed cloud resource", "", ""),
    },
})

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
           "localhost": "tarmoq: faqat localhost", "hidden": "yashirilgan: {b} ta baseline'da, {s} ta armorix-ignore bilan",
           "cached": "{n} ta fayl keshdan", "config": "sozlama", "baseline_written": "{n} ta topilma baseline'ga yozildi → {path}"},
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
           "localhost": "сеть: только localhost", "hidden": "скрыто: {b} в baseline, {s} через armorix-ignore",
           "cached": "файлов из кэша: {n}", "config": "настройки", "baseline_written": "в baseline записано находок: {n} → {path}"},
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
           "localhost": "network: localhost only", "hidden": "hidden: {b} in baseline, {s} by armorix-ignore",
           "cached": "{n} files from cache", "config": "config", "baseline_written": "wrote {n} finding(s) to the baseline → {path}"},
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
