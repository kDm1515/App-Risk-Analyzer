from androguard.core.apk import APK

def analyze_apk(apk_path):
    apk = APK(apk_path)

    app_info = {
        "app_name": apk.get_app_name(),
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "permissions": apk.get_permissions()
    }

    return app_info