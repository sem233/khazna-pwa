# ملف توضيحي — يُستخدم لبناء الـ APK بـ GitHub Actions

## بناء APK بـ Capacitor:

### المتطلبات على CI:
- Java 17 (JDK)
- Android SDK + NDK
- Node.js 20+

### خطوات البناء:
```bash
cd android-wrapper
npm install
npx cap sync android
cd android
./gradlew assembleRelease
```

### تعديل AndroidManifest.xml (بعد npx cap add android):

أضف هذه الصلاحيات في <manifest>:
```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
```

### Quick Settings Tile (notification shortcut):

في MainActivity.java:
```java
// Add Tile service
```

في AndroidManifest.xml:
```xml
<service
    android:name=".KhaznaQuickTileService"
    android:icon="@mipmap/ic_launcher"
    android:label="خزنة"
    android:permission="android.permission.BIND_QUICK_SETTINGS_TILE"
    android:exported="true">
    <intent-filter>
        <action android:name="android.service.quicksettings.action.QS_TILE" />
    </intent-filter>
</service>
```

### KhaznaQuickTileService.java:
```java
package com.khazna.passwordmanager;

import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import androidx.annotation.RequiresApi;

@RequiresApi(api = Build.VERSION_CODES.N)
public class KhaznaQuickTileService extends TileService {

    @Override
    public void onTileAdded() {
        super.onTileAdded();
        getQsTile().setState(Tile.STATE_INACTIVE);
        getQsTile().updateTile();
    }

    @Override
    public void onClick() {
        super.onClick();
        // Open the app in overlay/popup mode
        Intent intent = new Intent(getApplicationContext(), MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        intent.putExtra("KHAZNA_OVERLAY_MODE", true);
        startActivityAndCollapse(intent);
    }
}
```

### MainActivity.java — Popup/Overlay mode:
```java
// In onCreate(), check if opened from Quick Tile:
boolean overlayMode = getIntent().getBooleanExtra("KHAZNA_OVERLAY_MODE", false);
if (overlayMode) {
    // Set window size to popup dimensions
    WindowManager.LayoutParams params = getWindow().getAttributes();
    params.width = WindowManager.LayoutParams.WRAP_CONTENT;
    params.height = WindowManager.LayoutParams.WRAP_CONTENT;
    params.gravity = Gravity.CENTER;
    getWindow().setAttributes(params);
    
    // Load the app with popup=true param
    getBridge().getWebView().loadUrl(
        "https://khazna.app/?overlay=true"
    );
}
```
