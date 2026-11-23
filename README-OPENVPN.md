# OpenVPN Collector — راهنما | Guide

ماژول جدید و **کاملاً افزوده‌شده** به MSN Collector — هیچ‌کدام از فایل‌ها و Collectorهای قبلی تغییر نکرده‌اند؛ فقط این قابلیت اضافه شده است.
A purely additive module. Nothing from the existing pipeline was modified or touched.

---

## 📥 خروجی‌ها | Outputs

| فایل | توضیح |
|------|-------|
| [`openvpn.json`](https://raw.githubusercontent.com/hadipi00/msn-collector/main/openvpn.json) | متادیتای همه کانفیگ‌های OpenVPN (کشور، سرور، پورت، تاریخ، SHA256) — یک نسخه از آن داخل `mehdisedighinasab-openvpn.zip` هم هست |
| [`mehdisedighinasab-openvpn.zip`](https://raw.githubusercontent.com/hadipi00/msn-collector/main/mehdisedighinasab-openvpn.zip) | همه کانفیگ‌های .ovpn + پوشه VPNBook + credentials + `openvpn.json` |
| [`mehdisedighinasab-vpnbook.zip`](https://raw.githubusercontent.com/hadipi00/msn-collector/main/mehdisedighinasab-vpnbook.zip) | فقط کانفیگ‌های VPNBook — **بدون نیاز به ورود دستی** |
| `openvpn_state.json` | وضعیت: آخرین Message ID هر کانال، رجیستری hashها، شماره‌گذاری |
| `openvpn_last_update.txt` | زمان آخرین آپدیت |
| `openvpn_channels.txt` | کانال‌های تلگرام OpenVPN — قابل ویرایش مثل بقیه فایل‌ها |

نام فایل‌ها: `mehdisedighinasab-COUNTRY-NUMBER-TCP-PORT.ovpn`
مثال: `mehdisedighinasab-Germany-1-TCP-443.ovpn` — شماره‌گذاری هر کشور مستقل و **پایدار** است (در `openvpn_state.json` ثبت می‌شود).

## 📡 منابع | Sources

1. کانال‌های `openvpn_channels.txt`: `@super_Config_fast`، `@ConfigWireguard`، `@newconfig7`، `@pro_nic`، `@vasl_bashim`
2. وب: `https://www.vpnbook.com/freevpn/openvpn` (endpoint رسمی + احراز هویت خودکار)

فقط OpenVPN: فایل‌های WireGuard / V2Ray / VLESS / VMess / Trojan / SOCKS وارد این کالکتور **نمی‌شوند**.

## 🕐 تازگی | Freshness

- فقط پست‌های جدیدتر از `OPENVPN_FRESHNESS_HOURS` (پیش‌فرض **۲۴ ساعت**)
- آخرین Message ID پردازش‌شده هر کانال ذخیره می‌شود و پست‌های قدیمی دوباره بررسی نمی‌شوند
- برای بازیابی کنترل‌شده: `OPENVPN_REWIND=200 python3 openvpn_collector.py` (عقب‌گرد به اندازه N پیام)
- تکراری‌ها با SHA256 حذف می‌شوند؛ اگر کانفیگ جدید نبود، خروجی قبلی دست‌نخورده می‌ماند

## 🔐 دانلود پیوست‌های تلگرام (MTProto رسمی)

پیش‌نمایش `t.me/s/` فایل نمیدهد؛ برای دانلود پیوست‌های `.ovpn` باید یک‌بار اعتبارنامه رسمی MTProto تنظیم شود:

1. از [my.telegram.org](https://my.telegram.org) → API development tools → `api_id` و `api_hash` بگیرید
2. یک StringSession بسازید (روی سیستم خودتان، یک‌بار):
   ```bash
   pip3 install telethon
   python3 -c "
   from telethon.sync import TelegramClient
   from telethon.sessions import StringSession
   with TelegramClient(StringSession(), API_ID, API_HASH) as c:
       print(c.session.save())"
   ```
3. در محیط اجرای پروژه (سرور/Actions) این متغیرها را ست کنید:
   ```bash
   export OPENVPN_TG_API_ID=123456
   export OPENVPN_TG_API_HASH=abcd...
   export OPENVPN_TG_SESSION="1BQANOTEuMTA..."
   ```

بدون این متغیرها کالکتور همچنان کار می‌کند (VPNBook + کانفیگ‌های متنی) ولی پیوست‌ها را
«unavailable» گزارش می‌کند — **هیچ داده تقلبی تولید نمی‌شود**.

## 🔑 VPNBook — بدون ورود دستی

- Username/Password عمومی VPNBook خودکار از خود صفحه دریافت می‌شود (OCR هم به‌عنوان پشتیبان)
- داخل هر فایل `.ovpn` بلاک استاندارد OpenVPN 2.4+ تزریق می‌شود:
  ```
  <auth-user-pass>
  vpnbook
  ********
  </auth-user-pass>
  ```
- فایل `vpnbook_credentials.txt` هم برای کلاینت‌های قدیمی‌تر کنار بسته هست
- رمز هر ۱-۲ هفته عوض می‌شود؛ هر چرخه نسخه تازه دانلود و فایل‌های قدیمی **جایگزین** می‌شوند

> ⚠️ **هشدار امنیتی:** چون این بسته‌ها عمومی منتشر می‌شوند، رمز VPNBook عمومی است.
> برای مصرف حساس استفاده نکنید. با `VPNBOOK_EMBED_CREDS=0` می‌توانید تزریق رمز را
> خاموش کنید (فایل AUTH-REQUIRED.txt جایگزین می‌شود).

## 🚦 اجرا | Run

```bash
python3 openvpn_collector.py   # فقط OpenVPN | OpenVPN only
bash run.sh                    # هر سه کالکتور + پوش | all three + push
```

- خطای OpenVPN بقیه Collectorها را متوقف نمی‌کند (در run.sh با گارد `||` اجرا می‌شود)
- بدون کانفیگ جدید، ZIPها و JSON قبلی دست‌نخورده می‌مانند
- اعتبارنامه VPNBook هرگز در `openvpn.json` یا ریپو قرار نمی‌گیرد — فقط داخل بسته ZIP مربوطه

## ⚙️ متغیرهای محیطی | Environment

| متغیر | پیش‌فرض | توضیح |
|-------|---------|-------|
| `OPENVPN_FRESHNESS_HOURS` | 24 | حداکثر عمر پست برای شمردن «جدید» |
| `OPENVPN_RETENTION_HOURS` | 72 | مدت ماندن کانفیگ در ZIP |
| `OPENVPN_REWIND` | 0 | عقب‌گرد Message ID (بازیابی کنترل‌شده) |
| `OPENVPN_TG_API_ID/_HASH/_SESSION` | — | MTProto برای پیوست‌ها |
| `VPNBOOK_EMBED_CREDS` | 1 | تزریق خودکار رمز داخل ovpn |
| `OPENVPN_MAX_REGISTRY` | 3000 | سقف تعداد در JSON/state |
