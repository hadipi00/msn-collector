# OpenVPN Collector — راهنما | Guide

ماژول کامل OpenVPN در MSN Collector — جمع‌آوری، تازه‌سازی و بسته‌بندی خودکار فایل‌های `.ovpn`.

---

## 📥 خروجی‌ها | Outputs

| فایل | توضیح |
|------|-------|
| [`openvpn.zip`](https://raw.githubusercontent.com/hadipi00/msn-collector/main/openvpn.zip) | **بستهٔ واحد همهٔ کانفیگ‌ها** — همهٔ `.ovpn` ها ادغام‌شده در یک ZIP + `openvpn.json` + راهنمای کوتاه |
| [`openvpn/<name>.ovpn`](https://raw.githubusercontent.com/hadipi00/msn-collector/main/openvpn) | **تک‌فایل‌ها برای دانلود جدا** — هر سرور یک فایل مستقل، هر فایل با احراز هویت داخل خودش |
| [`openvpn.json`](https://raw.githubusercontent.com/hadipi00/msn-collector/main/openvpn.json) | متادیتای نمایشی (کشور، سرور، پورت، تاریخ) — بدون متن کانفیگ و بدون اطلاعات منبع |
| `openvpn_state.json` | وضعیت داخلی: آخرین Message ID هر کانال، رجیستری hashها، شماره‌گذاری |
| `openvpn_last_update.txt` | زمان آخرین آپدیت |
| `openvpn_channels.txt` | کانال‌های تلگرام — قابل ویرایش مثل بقیهٔ فایل‌ها |

نام فایل‌ها: `mehdisedighinasab-COUNTRY-NUMBER-TCP-PORT.ovpn`
مثال: `mehdisedighinasab-Germany-1-TCP-443.ovpn` — شماره‌گذاری هر کشور مستقل و **پایدار** است (در `openvpn_state.json` ثبت می‌شود).

بسته‌های قدیمی برنددار (`mehdisedighinasab-openvpn.zip` / `mehdisedighinasab-vpnbook.zip`) دیگر ساخته نمی‌شوند و در اولین اجرا از ریپو حذف می‌شوند.

## 🕐 تازگی | Freshness

- فقط پست‌های جدیدتر از `OPENVPN_FRESHNESS_HOURS` (پیش‌فرض **۲۴ ساعت**) از کانال‌های `openvpn_channels.txt`
- سرورهای عمومی وب با endpoint رسمی + احراز هویت خودکار به همان رجیستری اضافه می‌شوند
- آخرین Message ID پردازش‌شدهٔ هر کانال ذخیره می‌شود و پست‌های قدیمی دوباره بررسی نمی‌شوند
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

بدون این متغیرها کالکتور همچنان کار می‌کند (کانفیگ‌های متنی + سرورهای وب) ولی پیوست‌ها را
«unavailable» گزارش می‌کند — **هیچ داده تقلبی تولید نمی‌شود**.

## 🔑 بدون ورود دستی

- هر جا فایل `.ovpn` به نام کاربری/رمز نیاز داشته باشد، بلاک استاندارد OpenVPN 2.4+ داخل خود فایل تزریق می‌شود:
  ```
  <auth-user-pass>
  ********
  ********
  </auth-user-pass>
  ```
- همین‌طور تک‌فایل‌های `openvpn/<name>.ovpn` هم مستقل و آماده‌ی اتصال‌اند
- اعتبارنامه‌های اشتراکی هر ۱-۲ هفته عوض می‌شوند؛ هر چرخه نسخهٔ تازه دانلود و فایل‌ها **جایگزین** می‌شوند — کافیست دوباره دانلود کنید

> ⚠️ **هشدار امنیتی:** این بسته عمومی منتشر می‌شود و رمزها اشتراکی‌اند — برای مصرف حساس استفاده نکنید.
> با `VPNBOOK_EMBED_CREDS=0` می‌توانید تزریق رمز را خاموش کنید.

## 🚦 اجرا | Run

```bash
python3 openvpn_collector.py   # فقط OpenVPN | OpenVPN only
bash run.sh                    # همهٔ کالکتورها + پوش | all collectors + push
```

- خطای OpenVPN بقیهٔ Collectorها را متوقف نمی‌کند (در workflow با `continue-on-error` و در run.sh با گارد `||` اجرا می‌شود)
- بدون کانفیگ جدید، ZIP و JSON قبلی دست‌نخورده می‌مانند
- اعتبارنامه‌ها هرگز در `openvpn.json` یا فایل متنی جدا قرار نمی‌گیرند — فقط داخل خود فایل‌های `.ovpn`

## ⚙️ متغیرهای محیطی | Environment

| متغیر | پیش‌فرض | توضیح |
|-------|---------|-------|
| `OPENVPN_FRESHNESS_HOURS` | 24 | حداکثر عمر پست برای شمردن «جدید» |
| `OPENVPN_RETENTION_HOURS` | 72 | مدت ماندن کانفیگ در خروجی‌ها |
| `OPENVPN_REWIND` | 0 | عقب‌گرد Message ID (بازیابی کنترل‌شده) |
| `OPENVPN_TG_API_ID/_HASH/_SESSION` | — | MTProto برای پیوست‌ها |
| `VPNBOOK_EMBED_CREDS` | 1 | تزریق خودکار رمز داخل ovpn |
| `OPENVPN_MAX_REGISTRY` | 3000 | سقف تعداد در state |
