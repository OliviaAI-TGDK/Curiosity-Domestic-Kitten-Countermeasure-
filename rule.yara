/*
    Domestic Kitten / APT-C-50 / FurBall YARA Ruleset
    For curiosity.sh - Defensive Use Only
    Author: Olivian Security Collective
    Reference: APT-C-50
*/

import "android"
import "dex"

rule DomesticKitten_APK_FurBall_Core {
    meta:
        description = "Domestic Kitten FurBall core - Telegram Bot exfil"
        author = "Olivian Security"
        family = "Domestic Kitten"
        alias = "APT-C-50, FurBall"
        severity = "CRITICAL"
        date = "2026-07-23"
    strings:
        // Telegram C2 infra
        $c2_a = "api.telegram.org/bot" nocase
        $c2_b = "telegram-bot.com/api" nocase
        $c2_c = /bot[0-9]{8,12}:[A-Za-z0-9_-]{30,50}/
        $c2_d = "getMe" ascii wide
        $c2_e = "sendDocument" ascii wide
        $c2_f = "sendMessage" ascii wide

        // FurBall known package / strings
        $pkg_a = "com.furball" nocase
        $pkg_b = "com.domestic" nocase
        $pkg_c = "com.kitten" nocase
        $str_a = "FurBall" nocase
        $str_b = "islamic" nocase // often uses religious lures

        // Exfil behavior
        $exfil_a = "getExternalStorageDirectory" ascii wide
        $exfil_b = "/sdcard/DCIM" ascii wide
        $exfil_c = "/sdcard/WhatsApp" ascii wide
        $exfil_d = "READ_SMS" ascii wide
        $exfil_e = "READ_CONTACTS" ascii wide
        $exfil_f = "RECORD_AUDIO" ascii wide
        $exfil_g = "ACCESS_FINE_LOCATION" ascii wide

    condition:
        uint16(0) == 0x4B50 and // APK is ZIP
        (
            2 of ($c2_*) and 2 of ($exfil_*)
        ) or (
            1 of ($pkg_*) and 1 of ($c2_*) and 1 of ($exfil_*)
        ) or (
            all of ($c2_a,$c2_e,$c2_f)
        )
}

rule DomesticKitten_APK_Lure_Doc {
    meta:
        description = "Domestic Kitten lure APKs disguised as docs / gov apps"
        author = "Olivian Security"
        family = "Domestic Kitten"
    strings:
        $lure_a = "Warrant" nocase wide
        $lure_b = "Arrest" nocase wide
        $lure_c = "Ministry of" nocase wide
        $lure_d = "VIP" nocase wide
        $lure_e = "Application Form" nocase wide
        $lure_f = "Resume" nocase wide
        $icon_a = "android.intent.action.MAIN" wide
        $perm_a = "RECEIVE_BOOT_COMPLETED"
    condition:
        uint16(0) == 0x4B50 and
        2 of ($lure_*) and $icon_a
}

rule DomesticKitten_Dex_FurBall_Service {
    meta:
        description = "FurBall persistent service and exfil loops in DEX"
        author = "Olivian Security"
    strings:
        $service_a = "MyService" ascii wide
        $service_b = "BackgroundService" ascii wide
        $service_c = "UploadService" ascii wide
        $loop_a = "while (true)" ascii wide
        $loop_b = "Thread.sleep" ascii wide
        $exfil_a = "getLine1Number" ascii wide
        $exfil_b = "getDeviceId" ascii wide
        $exfil_c = "getSubscriberId" ascii wide
    condition:
        dex.number_of_dex_files > 0 and
        2 of ($service_*) and 2 of ($exfil_*)
}

rule DomesticKitten_AndroidManifest_Permissions {
    meta:
        description = "Heavy permission set typical for Domestic Kitten spyware"
        author = "Olivian Security"
    strings:
        $p1 = "android.permission.READ_SMS"
        $p2 = "android.permission.READ_CONTACTS"
        $p3 = "android.permission.READ_CALL_LOG"
        $p4 = "android.permission.RECORD_AUDIO"
        $p5 = "android.permission.ACCESS_FINE_LOCATION"
        $p6 = "android.permission.WRITE_EXTERNAL_STORAGE"
        $p7 = "android.permission.READ_EXTERNAL_STORAGE"
        $p8 = "android.permission.CAMERA"
    condition:
        6 of ($p*)
}

rule DomesticKitten_Telegram_Exfil_Path {
    meta:
        description = "Specific Telegram exfil file paths used by FurBall"
        author = "Olivian Security"
    strings:
        $path_a = "/sdcard/" ascii wide
        $path_b = "Telegram API" ascii wide
        $path_c = "/data/data/com.android.providers.telephony/databases/mmssms.db" ascii wide
        $path_d = "/data/data/com.android.providers.contacts/databases/contacts2.db" ascii wide
        $uri_a = "content://sms" ascii wide
        $uri_b = "content://contacts" ascii wide
    condition:
        2 of them
}

// Optional - add real SHA256s when you have confirmed samples
// rule DomesticKitten_Known_Hashes {
// meta:
// description = "Known Domestic Kitten hashes - add yours"
// condition:
// false // placeholder - add hash condition when you have samples
// }
