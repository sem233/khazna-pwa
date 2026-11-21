# Khazna Android — Quick Overlay Plugin
# Java plugin for notification shortcut → floating overlay

PLUGIN_JAVA = """
package com.khazna.overlay;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "KhaznaOverlay")
public class KhaznaOverlayPlugin extends Plugin {

    @PluginMethod
    public void requestOverlayPermission(PluginCall call) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!Settings.canDrawOverlays(getContext())) {
                Intent intent = new Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getContext().getPackageName())
                );
                startActivityForResult(call, intent, "overlayPermissionResult");
                return;
            }
        }
        call.resolve();
    }

    @PluginMethod
    public void canDrawOverlays(PluginCall call) {
        boolean can = true;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            can = Settings.canDrawOverlays(getContext());
        }
        JSObject ret = new JSObject();
        ret.put("value", can);
        call.resolve(ret);
    }
}
"""
