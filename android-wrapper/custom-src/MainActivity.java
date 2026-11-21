package com.khazna.passwordmanager;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;
import android.webkit.WebView;
import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

    private static final String CHANNEL_ID = "khazna_quick_access";
    private static final int NOTIFICATION_ID = 1001;
    private static final int REQ_POST_NOTIFICATIONS = 2001;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(NativeBiometricPlugin.class);
        super.onCreate(savedInstanceState);

        // Protect vault screens from screenshots and recents thumbnail leaks
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);

        createNotificationChannel();
        ensureNotificationPermissionAndShow();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_POST_NOTIFICATIONS && grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            showPersistentQuickNotification();
        }
    }

    private void ensureNotificationPermissionAndShow() {
        if (Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    new String[]{Manifest.permission.POST_NOTIFICATIONS},
                    REQ_POST_NOTIFICATIONS
                );
                return;
            }
        }
        showPersistentQuickNotification();
    }

    private void handleIntent(Intent intent) {
        if (intent != null && intent.getBooleanExtra("overlay", false)) {
            if (getBridge() == null) return;
            WebView webView = getBridge().getWebView();
            if (webView != null) {
                final String js = "window.__pendingOverlayMode = true; if (typeof window.__activateOverlayMode === 'function') { window.__activateOverlayMode(); }";
                // Retry at staggered intervals so both warm-resume and cold-start WebView loads activate overlay reliably
                int[] delays = new int[]{250, 800, 1600};
                for (int delay : delays) {
                    webView.postDelayed(() -> webView.evaluateJavascript(js, null), delay);
                }
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
                .setSmallIcon(R.drawable.ic_khazna_tile)
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
