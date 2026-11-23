# MSN Collector — ALL-IN-ONE | کالکتور همه‌کاره

> همهٔ کالکتورها یکجا: **V2Ray/Xray + MTProto/SOCKS + WireGuard** — هر ۲ ساعت آپدیت می‌شود
> Everything in one repo: **V2Ray/Xray + MTProto/SOCKS + WireGuard** — refreshed every 2 hours

---

## 📡 لینک‌های اشتراک | Subscription Links

### ساب کامل (همه پروتکل‌ها) | Full subscription (all protocols)

| فرمت | لینک |
|------|------|
| Base64 — پیشنهادی برای v2rayNG / Hiddify / NekoBox | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/sub.txt` |
| نرمال (متن ساده) | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/all.txt` |

### ساب هر پروتکل | Per-protocol subscriptions

| پروتکل | نرمال (Plain) | Base64 |
|--------|---------------|--------|
| VLESS | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/vless.txt` | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/vless_b64.txt` |
| VMess | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/vmess.txt` | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/vmess_b64.txt` |
| Trojan | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/trojan.txt` | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/trojan_b64.txt` |
| Shadowsocks | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/ss.txt` | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/ss_b64.txt` |
| ShadowsocksR | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/ssr.txt` | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/ssr_b64.txt` |
| Hysteria2 | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/hysteria2.txt` | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/hysteria2_b64.txt` |
| TUIC | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/tuic.txt` | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/tuic_b64.txt` |

### 🔵 پروکسی تلگرام | Telegram MTProto / SOCKS5

| ساب | لینک |
|-----|------|
| MTProto (tg://proxy) | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/mtproto.txt` |
| SOCKS5 (tg://socks) | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/mtproto_socks.txt` |
| همه با هم + Base64 | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/mtproto_all.txt` |

### 🛡️ WireGuard

| ساب | لینک |
|-----|------|
| wireguard:// لینک (Hiddify / NekoBox / v2rayNG جدید) | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/wireguard.txt` |
| Base64 | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/wireguard_b64.txt` |
| فایل کانفیگ .conf (اپ رسمی WireGuard / AmneziaWG) | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/wireguard_conf.txt` |

### 🔶 OpenVPN

| خروجی | توضیح |
|-------|-------|
| `openvpn.json` | متادیتای کامل کانفیگ‌های OpenVPN (کشور، سرور، پورت، تاریخ، SHA256) — `https://raw.githubusercontent.com/hadipi00/msn-collector/main/openvpn.json` |
| ZIP کامل | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/mehdisedighinasab-openvpn.zip` |
| ZIP مخصوص VPNBook (بدون ورود دستی) | `https://raw.githubusercontent.com/hadipi00/msn-collector/main/mehdisedighinasab-vpnbook.zip` |

> منابع: کانال‌های `openvpn_channels.txt` + VPNBook — فقط پست‌های ۲۴ ساعت اخیر جمع می‌شود و
> پیوست‌های `.ovpn` با MTProto رسمی دانلود می‌شوند (راهنما: `README-OPENVPN.md`).

> ⚠️ فایل پروتکلی که در اجرای فعلی کانفیگ زنده نداشته باشد، ساخته نمی‌شود (مثلاً اگر هیچ TUIC زنده‌ای نباشد، `tuic.txt` وجود ندارد).
> ⚠️ Protocol files with zero alive configs in the current run are not created.

### 🏷 نام کانفیگ‌ها | Config names

همهٔ کانفیگ‌ها با پرچم و کد کشور سرور نام‌گذاری می‌شوند: `@mehdisedighinasab-12-🇩🇪DE` یعنی کانفیگ شمارهٔ ۱۲ با سرور آلمان. اگر کشور سرور تشخیص داده نشود فقط شماره می‌آید: `@mehdisedighinasab-7`.
کانفیگ‌های WireGuard هم همین الگو را دارند: `@mehdisedighinasab-1-🇦🇱AL`.

All configs are auto-renamed with the server's country flag + ISO code: `@mehdisedighinasab-12-🇩🇪DE` = config #12 on a German server. Unknown country → number only. WireGuard configs follow the same pattern.

> فایل‌های پروتکلی که در اجرای فعلی کانفیگ زنده نداشته باشند ساخته نمی‌شوند؛ کانفیگ‌های MTProto/SOCKS و WireGuard هم فقط بعد از چک زنده‌بودن (TCP) در لیست می‌روند.
> Protocol files with zero alive configs in the current run are not created. MTProto/SOCKS/WG items are alive-checked before being listed.

---

## ✨ چه می‌کند؟ | What does it do?

1. **هر ۲ ساعت** همه ساب‌لینک‌های فایل `sources.txt` را دانلود می‌کند
2. همه کانفیگ‌ها را پارس و **تکراری‌ها را حذف** می‌کند (vmess / vless / trojan / ss / ssr / hysteria / hysteria2 / tuic)
3. هر کانفیگ را **چک می‌کند**: فقط کانفیگ‌هایی که پورتشان زنده و پاسخگو باشد در لیست می‌رود؛ خاموش‌ها حذف می‌شوند
4. **پروکسی‌های تلگرام** (MTProto / SOCKS5) را از کانال‌های فایل `channels.txt` برمی‌دارد، چک زنده می‌کند و جدا خروجی می‌دهد
5. **کانفیگ‌های WireGuard** را از کانال‌های فایل `wireguard_channels.txt` برمی‌دارد (شامل AmneziaWG) و به سه فرمت لینک / Base64 / .conf خروجی می‌دهد
6. خروجی هر پروتکل در **فایل جداگانه** نوشته می‌شود — فایل‌های قبلی کامل پاک و فایل‌های جدید جایگزین می‌شوند
7. آمار در `stats.json` (V2Ray) و `mtproto_stats.json` (MTProto/WG) و زمان آخرین آپدیت در `last_update.txt` ذخیره می‌شود

## ✏️ افزودن/حذف منبع | Add / remove sources

چهار فایل قابل ویرایش مستقیم در همین صفحه (دکمه Edit):

- **`sources.txt`** — لینک‌های ساب V2Ray (هر خط = یک لینک)
- **`channels.txt`** — کانال‌های تلگرام پروکسی MTProto/SOCKS (هر خط = یک @کانال)
- **`wireguard_channels.txt`** — کانال‌های تلگرام کانفیگ WireGuard
- **`openvpn_channels.txt`** — کانال‌های تلگرام کانفیگ OpenVPN (پیوست‌ها با MTProto رسمی — `README-OPENVPN.md`)

در هر سه فایل:

- خط‌هایی که با `#` شروع شوند نادیده گرفته می‌شوند
- برای حذف منبع، خطش را پاک کنید؛ برای افزودن، مورد جدید در خط جدید بگذارید
- عدد جلوی هر خط — شمارش خودکار همان منبع (کل / زنده) است و بعد از هر چرخه بازنویسی می‌شود؛ دستی ویرایشش نکنید
- تغییرات در چرخه بعدی (حداکثر ۲ ساعت بعد) اعمال می‌شود

## 📊 فایل‌های خروجی | Output files

| فایل | توضیح |
|------|-------|
| `sub.txt` | ساب کامل Base64 — برای ایمپورت مستقیم در v2rayNG / Hiddify / NekoBox |
| `all.txt` | ساب کامل نرمال — همه کانفیگ‌های زنده به صورت متن ساده |
| `vless.txt` / `vless_b64.txt` | کانفیگ‌های VLESS زنده |
| `vmess.txt` / `vmess_b64.txt` | کانفیگ‌های VMess زنده |
| `trojan.txt` / `trojan_b64.txt` | کانفیگ‌های Trojan زنده |
| `ss.txt` / `ss_b64.txt` | کانفیگ‌های Shadowsocks زنده |
| `hysteria2.txt` / `hysteria2_b64.txt` | کانفیگ‌های Hysteria2 زنده |
| `tuic.txt` / `tuic_b64.txt` | کانفیگ‌های TUIC زنده |
| `ssr.txt` / `ssr_b64.txt` | کانفیگ‌های ShadowsocksR زنده |
| `mtproto.txt` | پروکسی‌های زندهٔ MTProto تلگرام (tg://proxy) — کانال‌ها + API وب proxybolt.link |
| `mtproto_socks.txt` | پروکسی‌های زندهٔ SOCKS5 تلگرام (tg://socks) |
| `mtproto_all.txt` | هر دو نوع پروکسی تلگرام + نسخهٔ Base64 |
| `plain_http.txt` | پروکسی‌های زندهٔ HTTP از خروجی‌های رسمی publicvpnlist.com |
| `plain_socks4.txt` | پروکسی‌های زندهٔ SOCKS4 از publicvpnlist.com |
| `plain_socks5.txt` | پروکسی‌های زندهٔ SOCKS5 از publicvpnlist.com |
| `plain_all.txt` | هر سه نوع پروکسی بالا در یک فایل (protocol://IP:port) |
| `plain_all.csv` | همان لیست با متادیتا (کشور، پینگ، زمان چک منبع) |
| `wireguard.txt` / `wireguard_b64.txt` | کانفیگ‌های WireGuard به صورت لینک wireguard:// + Base64 |
| `wireguard_conf.txt` | همان کانفیگ‌ها به صورت بلوک .conf برای اپ رسمی WireGuard / AmneziaWG |
| `openvpn.json` | متادیتای کانفیگ‌های OpenVPN (کشور/سرور/پورت/تاریخ/SHA256) |
| `mehdisedighinasab-openvpn.zip` / `mehdisedighinasab-vpnbook.zip` | بسته‌های .ovpn با نام‌گذاری mehdisedighinasab-COUNTRY-N-TCP/UDP-PORT |
| `stats.json` | آمار آخرین اجرای V2Ray |
| `mtproto_stats.json` | آمار آخرین اجرای MTProto/WireGuard |
| `plain_stats.json` | آمار آخرین اجرای کالکتور پروکسی‌های ساده |
| `last_update.txt` / `mtproto_last_update.txt` / `plain_last_update.txt` | زمان آخرین آپدیت هر بخش |

## 🔧 اجرای دستی | Manual run

```bash
python3 collector.py            # فقط V2Ray | V2Ray only
python3 mtproto_collector.py    # فقط MTProto + WireGuard | MTProto + WG only
python3 openvpn_collector.py    # فقط OpenVPN | OpenVPN only
python3 plain_proxy_collector.py # فقط HTTP/SOCKS4/SOCKS5 | plain proxies only
bash run.sh                     # هر چهار + پوش | all four + push
```

## 🔌 منابع وب | Web API sources (built-in)

این دو منبع داخل خود کالکتورها ساخته‌شده‌اند و هر ۲ ساعت خودکار چک می‌شوند — نیازی به sources.txt ندارند:

| منبع | پروتکل | جای کد |
|------|--------|--------|
| [proxybolt.link](https://proxybolt.link/) | MTProto تلگرام (tg://proxy) — همهٔ صفحات API | `mtproto_collector.py → fetch_proxybolt()` |
| [publicvpnlist.com](https://publicvpnlist.com/) | HTTP / SOCKS4 / SOCKS5 — خروجی رسمی JSON سایت | `plain_proxy_collector.py` |

> نکته: دیتاست‌های VPN در سطح سرور publicvpnlist (OpenVPN، VLESS، Trojan، VMess، Shadowsocks، Hysteria2، TUIC، WireGuard، IKEv2) پشت کلید ۲۴ساعتهٔ reCAPTCHA هستند و دریافت خودکار ندارند؛ فقط خروجی‌های رایگان پروکسی آن سایت اتومات شده‌اند.

## ⏰ زمان‌بندی | Automation

- **روش فعلی:** اسکریپت زمان‌بند هر ۲ ساعت اجرا و خروجی‌ها را کامیت و پوش می‌کند
- **روش جایگزین (GitHub):** اگر این ریپو را به GitHub میرور کنید، ورک‌فلو `.github/workflows/collector.yml` خودکار هر ۲ ساعت اجرا می‌شود

### (اختیاری) جلوگیری از بزرگ شدن ریپو | Optional: keep repo small

به صورت پیش‌فرض هر آپدیت یک کامیت جدید است و تاریخچه کم‌کم بزرگ می‌شود. اگر در تنظیمات پروژه گزینهٔ **Force Push** را فعال کنید (Project → Settings → Main → Allow force push)، اسکریپت به صورت خودکار تاریخچه را تک‌کامیتی نگه می‌دارد و حجم ریپو ثابت می‌ماند.

By default each update adds a commit. If you enable **force push** in project settings, `run.sh` automatically collapses history to a single commit and the repo size stays constant.

---

**MSN Collector** — built for @mehdisedighinasab 🚀
