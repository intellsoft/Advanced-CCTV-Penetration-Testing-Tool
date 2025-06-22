# ابزار تست نفوذ پیشرفته دوربین‌های مداربسته (Kill-CCTV)

⚠️ **هشدار جدی: لطفاً قبل از استفاده، این متن را کامل بخوانید!** ⚠️

## 🧠 معرفی

این ابزار برای **تست نفوذ شبکه دوربین‌های مداربسته** طراحی شده و قادر است به‌طور خودکار:

- شبکه را شناسایی کند،
- دوربین‌های متصل را اسکن نماید،
- حملاتی مانند **Flood ICMP**, **Flood HTTP**, **RTSP flood**, **حمله به صفحات ورود** و **ARP Spoofing** را اجرا کند.

هدف از توسعه این ابزار، استفاده در پروژه‌های تحقیقاتی، یادگیری امنیت شبکه و ارزیابی‌های مجاز امنیتی است.

## 🚨 هشدارهای امنیتی و اخلاقی

✅ این نرم‌افزار فقط و فقط برای **مقاصد قانونی، آموزشی و با مجوز صریح از صاحب شبکه هدف** طراحی شده است.  
⛔ استفاده بدون مجوز از این ابزار، **غیرقانونی** و **غیراخلاقی** است و ممکن است پیگرد قضایی داشته باشد.

با استفاده از این برنامه، شما موافقت می‌کنید که:

- 🔐 مجوز صریح برای تست شبکه هدف دارید؛  
- 👨‍⚖️ با قوانین امنیت سایبری منطقه خود آشنایی دارید؛  
- 🛡️ از این ابزار برای مقاصد خرابکارانه استفاده نخواهید کرد؛  
- 🧾 مسئولیت کامل تمام عواقب ناشی از استفاده را شخصاً می‌پذیرید.

❗ حملات این نرم‌افزار ممکن است باعث اختلال، قطع دسترسی یا آسیب به سیستم‌های هدف شود.  
❗ دسترسی غیرمجاز به سیستم‌های الکترونیکی جرم محسوب می‌شود.


## ✨ تصاویر برنامه

![تصاویر برنامه](https://lh3.googleusercontent.com/d/1vixSGke8Ap90hy3dUN8QWVyedK1wwZrv)


## ⚙️ ویژگی‌ها

- تشخیص خودکار شبکه‌های فعال
- اسکن سریع دوربین‌های مداربسته با پورت‌های رایج
- چندین نوع حمله همزمان با Threading
- انتخاب هدف به‌صورت تک، جمعی یا دلخواه
- پشتیبانی از حمله ARP Spoofing برای شنود ترافیک

## 🖥️ سیستم‌های پشتیبانی‌شده

- Windows (با دسترسی Administrator)
- Linux/macOS (با دسترسی root)

## 🧪 وابستگی‌ها

- Python 3.7+
- کتابخانه‌های موردنیاز:
  - `scapy`
  - `requests`

## ▶️ نحوه اجرا

```bash
sudo python kill-cctv-v2.py
```

یا در ویندوز:

```cmd
python kill-cctv-v2.py
```


## برنامه نویس: محمدعلی عباسپور
[آسیب‌پذیری‌های دوربین‌های مداربسته در شبکه‌های داخلی](https://intellsoft.ir/cctv-camera-vulnerabilities-in-internal-networks/)

---

# Advanced CCTV Penetration Testing Tool

⚠️ **WARNING: READ BEFORE USE!** ⚠️

## 🧠 About

This tool is designed for **penetration testing of CCTV networks**, with features like:

* Network auto-discovery
* IP scanning for CCTV devices
* Multiple simultaneous attacks: ICMP Flood, HTTP Flood, RTSP Flood, Login brute, ARP Spoof

**For educational, authorized testing and research purposes only.**

## 🚨 Security and Ethical Warnings

* 🚫 Unauthorized use is illegal and unethical
* ✅ You must have **explicit permission** from the network owner
* 👨‍⚖️ You must understand local cybersecurity laws
* ⚠️ Attacks may disrupt or damage systems
* 📜 You bear **full responsibility** for any outcomes

**By using this software, you agree to these terms.**

## ⚙️ Features

* Auto-detects local networks
* Fast multithreaded scanning of common CCTV ports
* Target selection (individual/mass/custom)
* ARP Spoofing for MITM attacks
* Modular attack threads per camera

## 🖥️ Supported Systems

* Windows (Admin privileges)
* Linux/macOS (Root access)

## 🧪 Dependencies

* Python 3.7+
* Required libraries:

  * `scapy`
  * `requests`

## ▶️ Usage

```bash
sudo python kill-cctv-v2.py
```

Or on Windows:

```cmd
python kill-cctv-v2.py
```

---

💣 **مسئولیت کامل استفاده از این ابزار، به‌طور کامل بر عهده کاربر است.**
⚖️ نویسنده هیچ‌گونه مسئولیتی در قبال استفاده نادرست یا پیامدهای حقوقی ندارد.
