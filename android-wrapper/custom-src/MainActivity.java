package com.khazna.passwordmanager;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.webkit.WebView;
import androidx.core.app.NotificationCompat;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

    private static final String CHANNEL_ID = "khazna_quick_access";
    private static final int NOTIFICATION_ID = 1001;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(NativeBiometricPlugin.class);
        super.onCreate(savedInstanceState);
        createNotificationChannel();
        showPersistentQuickNotification();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent != null && intent.getBooleanExtra("overlay", false)) {
            WebView webView = getBridge().getWebView();
            if (webView != null) {
                webView.postDelayed(() -> {
                    webView.evaluateJavascript(
                        "window.__activateOverlayMode && window.__activateOverlayMode();",
                        null
                    );
                }, 300);
            }
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = "وصول سريع لخزنة";
            String description = "إشعار دائم للوصول السريع لكلمات المرور والملاحظات في نافذة عائمة";
            int importance = NotificationManager.IMPORTANCE_LOW;
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);
            channel.setShowBadge(false);

            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            if (notificationManager != null) {
                notificationManager.createNotificationChannel(channel);
            }
        }
    }

    private void showPersistentQuickNotification() {
        try {
            Intent intent = new Intent(this, MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            intent.putExtra("overlay", true);

            int flags = PendingIntent.FLAG_UPDATE_CURRENT;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                flags |= PendingIntent.FLAG_IMMUTABLE;
            }

            PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, flags);

            NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle("خزنة — وصول سريع")
                .setContentText("اضغط للفتح في نافذة عائمة فوق التطبيقات")
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOngoing(true)
                .setContentIntent(pendingIntent);

            NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (notificationManager != null) {
                notificationManager.notify(NOTIFICATION_ID, builder.build());
            }
        } catch (Exception ignored) {
            // Notifications may be denied on Android 13+ without runtime permission
        }
    }
}
