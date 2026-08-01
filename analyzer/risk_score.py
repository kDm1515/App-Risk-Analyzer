HIGH_RISK = {
    "android.permission.READ_SMS": 30,
    "android.permission.SEND_SMS": 30,
    "android.permission.READ_CONTACTS": 25,
    "android.permission.WRITE_CONTACTS": 25,
    "android.permission.ACCESS_FINE_LOCATION": 20,
    "android.permission.RECORD_AUDIO": 20,
    "android.permission.CAMERA": 15
}

MEDIUM_RISK = {
    "android.permission.ACCESS_COARSE_LOCATION": 10,
    "android.permission.READ_EXTERNAL_STORAGE": 10,
    "android.permission.WRITE_EXTERNAL_STORAGE": 10,
    "android.permission.BLUETOOTH": 5
}


PERMISSION_NAMES = {
    "android.permission.READ_SMS": "Read SMS",
    "android.permission.SEND_SMS": "Send SMS",
    "android.permission.READ_CONTACTS": "Read Contacts",
    "android.permission.WRITE_CONTACTS": "Write Contacts",
    "android.permission.ACCESS_FINE_LOCATION": "Precise Location",
    "android.permission.ACCESS_COARSE_LOCATION": "Location",
    "android.permission.RECORD_AUDIO": "Microphone",
    "android.permission.CAMERA": "Camera",
    "android.permission.INTERNET": "Internet",
    "android.permission.ACCESS_NETWORK_STATE": "Network Status",
    "android.permission.ACCESS_WIFI_STATE": "Wi-Fi",
    "android.permission.READ_EXTERNAL_STORAGE": "Storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Storage",
    "android.permission.BLUETOOTH": "Bluetooth",
    "android.permission.VIBRATE": "Vibration",
    "android.permission.FOREGROUND_SERVICE": "Foreground Service",
    "android.permission.SYSTEM_ALERT_WINDOW": "Display Over Other Apps",
    "android.permission.SYSTEM_OVERLAY_WINDOW": "Overlay Window",
    "android.permission.GET_TASKS": "Running Apps",
    "android.permission.WRITE_SECURE_SETTINGS": "Modify System Settings",
    "android.permission.INTERACT_ACROSS_USERS_FULL": "Multi-user Access"
}


def calculate_risk(permissions):
    score = 0
    permission_details = []

    for permission in permissions:
        if permission in HIGH_RISK:
            score += HIGH_RISK[permission]
            level = "High"

        elif permission in MEDIUM_RISK:
            score += MEDIUM_RISK[permission]
            level = "Medium"

        else:
            level = "Low"

        permission_details.append({
        "permission": PERMISSION_NAMES.get(permission, permission.split(".")[-1].replace("_", " ").title()),
        "risk": level

        })

    score = min(score, 100)

    if score >= 70:
        verdict = "High Risk"
    elif score >= 40:
        verdict = "Medium Risk"
    else:
        verdict = "Low Risk"

    return {
        "score": score,
        "verdict": verdict,
        "permissions": permission_details
    }