# پچ دستی دو آسیب‌پذیری PHP

تاریخ بررسی منابع: ۲۲ اکتبر ۲۰۲۶. این راهنما برای سرورهای تحت مدیریت خودتان است. ابتدا backup و زمان کوتاه نگه‌داری در نظر بگیرید و یک سرور آزمایشی را جلوتر انجام دهید. دستورها را با نوع نصب خود تطبیق دهید؛ این صفحه هیچ فرمانی خودکار اجرا نمی‌کند.

## چه چیزی باید اصلاح شود؟

دو شناسه `CVE-2026-109618` و `CVE-2026-109619` به خرابی حافظه در PHP مربوط‌اند و می‌توانند به اجرای کد از راه دور منجر شوند. طبق [اطلاعیه رسمی PHP](https://www.php.net/archive/2026.php)، نسخه‌های upstream اصلاح‌شده عبارت‌اند از:

| شاخه | حداقل نسخه اصلاح‌شده upstream |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

شماره ظاهراً قدیمی‌تر به‌تنهایی آسیب‌پذیری را ثابت نمی‌کند؛ توزیع ممکن است وصله را backport کرده باشد. معیار، نسخه کامل بسته و اطلاعیه همان سازنده است. برای PHP قدیمی‌تر از 8.2 به بسته دارای وصله معتبر vendor یا مهاجرت آزموده‌شده نیاز دارید؛ ارتقای major را کورکورانه انجام ندهید.

## شناسایی نصب

```bash
cat /etc/os-release
php -v
command -v php
systemctl list-units --type=service --state=running --no-pager
```

ممکن است PHP خط فرمان، PHP-FPM، Apache و Docker نسخه‌های متفاوت داشته باشند. داشتن چند نسخه یعنی همه نسخه‌هایی که درخواست وب پردازش می‌کنند باید بررسی شوند. برای نصب غیر استاندارد یا کنترل‌پنل، دستورالعمل همان vendor را دنبال کنید.

## Ubuntu / Debian: فقط بسته‌های نصب‌شده

فهرست بسته و candidate را ببینید. بسته عمومی `php-common` با نسخه‌ای مثل `2:92ubuntu1` نسخه موتور PHP نیست.

```bash
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' '*php*' 2>/dev/null
apt-cache policy php8.1-cli php8.1-common php8.1-fpm
```

در دستور دوم شاخه را مطابق نصب عوض کنید. طبق [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)، نمونه‌های Ubuntu اصلاح‌شده چنین‌اند:

| Ubuntu | شاخه | حداقل نسخه کامل بسته |
|---|---|---|
| 22.04 | php8.1 | 8.1.2-1ubuntu2.28 |
| 24.04 | php8.3 | 8.3.6-0ubuntu0.24.04.13 |
| 26.04 | php8.5 | 8.5.4-0ubuntu1.5 |
| 26.10 | php8.5 | 8.5.9-0ubuntu2.1 |

برای Debian، وضعیت را از [security tracker](https://security-tracker.debian.org/tracker/CVE-2026-109619) و اطلاعیه امنیتی همان release بررسی کنید. بسته Sury یا مخزن شخص ثالث باید با شواهد همان مخزن بررسی شود؛ جایگزینی مخزن یا شاخه را به نام رفع mirror انجام ندهید.

این قطعه را در **Bash** اجرا کنید؛ فقط بسته‌های PHP نصب‌شده را انتخاب می‌کند و قبل از نصب شبیه‌سازی انجام می‌دهد:

```bash
mapfile -t PHP_PACKAGES < <(
  dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' '*php*' 2>/dev/null |
  awk '$2 == "installed" && ($1 ~ /^php/ || $1 ~ /^libapache2-mod-php/) { print $1 }'
)
printf '%s\n' "${PHP_PACKAGES[@]}"
```

اگر آرایه خالی بود، دستور نصب را اجرا نکنید؛ مسیر نصب را پیدا کنید. برای آرایه غیرخالی:

```bash
sudo apt-get update -o APT::Update::Error-Mode=any
[ "${#PHP_PACKAGES[@]}" -gt 0 ] && sudo apt-get --simulate --no-remove --only-upgrade install "${PHP_PACKAGES[@]}"
# فهرست تغییرات را بخوانید؛ در صورت درست‌بودن:
[ "${#PHP_PACKAGES[@]}" -gt 0 ] && sudo apt-get --no-remove --only-upgrade install "${PHP_PACKAGES[@]}"
```

فقط سرویس‌های واقعاً استفاده‌شده را restart و وضعیتشان را بررسی کنید؛ مثلاً:

```bash
# مثال PHP-FPM در Ubuntu 22.04؛ در نصب دیگر نام سرویس را عوض کنید:
sudo systemctl restart php8.1-fpm
sudo systemctl is-active php8.1-fpm
# برای نصب mod_php، به‌جای FPM:
sudo systemctl restart apache2
sudo systemctl is-active apache2
```

هر دو مثال را بدون وجود آن سرویس‌ها اجرا نکنید. daemonهای worker/queue برنامه که PHP قدیمی را در حافظه دارند نیز باید طبق دستورالعمل برنامه restart شوند.

## AlmaLinux / DNF / Remi

اول تشخیص دهید بسته از کدام مخزن و stream است:

```bash
rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' | grep '^php'
dnf repolist
# فقط در نسخه‌های دارای ماژول PHP:
dnf module list php --enabled
```

فهرست بسته‌های PHP نصب‌شده را بگیرید:

```bash
mapfile -t PHP_PACKAGES < <(rpm -qa --qf '%{NAME}\n' | grep '^php')
printf '%s\n' "${PHP_PACKAGES[@]}"
```

برای آرایه غیرخالی، فهرست تغییرات را بررسی و سپس نصب کنید:

```bash
[ "${#PHP_PACKAGES[@]}" -gt 0 ] && sudo dnf --refresh check-update "${PHP_PACKAGES[@]}"
# خروجی 100 در check-update به معنی وجود آپدیت است، نه خطای نصب.
[ "${#PHP_PACKAGES[@]}" -gt 0 ] && sudo dnf --refresh upgrade --assumeno "${PHP_PACKAGES[@]}"
# انصرافِ --assumeno ممکن است exit غیرصفر بدهد؛ فهرست را بررسی کنید.
[ "${#PHP_PACKAGES[@]}" -gt 0 ] && sudo dnf --refresh upgrade "${PHP_PACKAGES[@]}"
```

stream، مخزن و شاخه فعلی را حفظ کنید. از `--nogpgcheck`، `--allowerasing`، reset ماژول یا `distro-sync` به‌عنوان راه‌حل عمومی استفاده نکنید. اگر بسته اصلاح‌شده هنوز candidate نیست، تکرار همان upgrade آن را ایجاد نمی‌کند؛ اطلاعیه و مخزن واقعی vendor باید بررسی شود. `php8.4.12` upstream پیش از نسخه اصلاح‌شده این شاخه است، ولی برای بسته vendor همیشه release کامل و وجود وصله را هم بررسی کنید.

پس از نصب، سرویس فعال را restart کنید؛ برای نصب معمول:

```bash
sudo systemctl restart php-fpm
sudo systemctl is-active php-fpm
# اگر Apache واقعاً از mod_php استفاده می‌کند:
sudo systemctl restart httpd
```

در نصب parallel، نام سرویس متفاوت است. [مخازن AlmaLinux](https://wiki.almalinux.org/repos/AlmaLinux.html) و [اطلاعیه vendor](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/) را بررسی کنید.

## Docker / Compose

آپدیت میزبان، PHP داخل image را اصلاح نمی‌کند. از پوشه، نام پروژه و فایل Compose اصلی استفاده کنید؛ نمونه زیر سرویس `app` را فرض می‌کند:

```bash
docker compose exec -T app php -r 'echo PHP_VERSION, PHP_EOL;'
```

ابتدا مطمئن شوید image تنظیم‌شده واقعاً نسخه اصلاح‌شده دارد؛ tag/digest ثابت قدیمی باید با نسخه سازگار اصلاح‌شده جایگزین شود. سپس:

```bash
docker compose pull app
docker compose up -d --no-deps --no-build --wait --wait-timeout 120 app
docker compose exec -T app php -r 'echo PHP_VERSION, PHP_EOL;'
```

اگر image سفارشی دارید، Dockerfile/base image را اصلاح کنید و قبل از جایگزینی بسازید:

```bash
docker compose build --pull app
docker compose up -d --no-deps --no-build --wait --wait-timeout 120 app
```

بدون healthcheck، `--wait` صرفاً running بودن را بررسی می‌کند. database، volumes و سایر سرویس‌ها را بی‌دلیل recreate یا حذف نکنید. برای پروژه‌ای که با `-p` یا `-f` اجرا شده، همان گزینه‌ها را در تمام دستورها حفظ کنید.

## اگر mirror یا دسترسی خطا داد

| خطا | اقدام درست |
|---|---|
| SSH timeout/refused | پورت، مسیر/VPN، فایروال و روشن‌بودن سرور را بررسی کنید؛ خطای PHP نیست. |
| not in the sudoers file | از حساب دارای مجوز استفاده کنید؛ رمز درست به‌تنهایی مجوز مدیریتی نمی‌دهد. |
| DNS / TLS | resolver، ساعت، certificate و مسیر بررسی شوند؛ TLS خاموش نشود. |
| امضا/NO_PUBKEY | کلید از منبع رسمی همان vendor بررسی شود؛ بررسی امضا حذف نشود. |
| 404 / بسته مفقود | release، معماری و sync مخزن بررسی شود؛ از mirror رسمی همان release استفاده کنید. |
| lock | منتظر پایان مدیر بسته بمانید؛ فایل قفل را کورکورانه حذف نکنید. |
| dependency | تغییرات پیشنهادی را بخوانید؛ حذف اجباری بسته‌ها راه‌حل عمومی نیست. |

## بررسی نهایی

نسخه کامل بسته‌های نصب‌شده، نسخه داخل هر container، سرویس‌های restartشده و endpoint واقعی برنامه را بررسی کنید. فقط `php -v` یا HTTP 200، همه workerها و همه مسیرهای نصب را اثبات نمی‌کند. تست upload، login، queue و کارکردهای اصلی برنامه را متناسب با سرویس انجام دهید. اگر وصله فعلاً قابل نصب نیست، سطح دسترسی عمومی را طبق طرح عملیاتی خود محدود و راهنمای کاهش مواجهه [PHP](https://www.php.net/archive/2026.php) را دنبال کنید؛ تغییر تنظیمات به‌تنهایی رفع کامل این دو CVE نیست.
