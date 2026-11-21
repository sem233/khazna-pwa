package com.khazna.passwordmanager;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.concurrent.Executor;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

@CapacitorPlugin(name = "NativeBiometric")
public class NativeBiometricPlugin extends Plugin {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS_PREFIX = "khazna_bio_key_";
    private static final String PREF_NAME = "khazna_biometric_prefs";
    private static final int GCM_TAG_LENGTH = 128;

    @PluginMethod
    public void isAvailable(PluginCall call) {
        try {
            BiometricManager biometricManager = BiometricManager.from(getContext());
            int canAuthenticate = biometricManager.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.BIOMETRIC_WEAK
            );
            boolean isAvailable = (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS);
            boolean hasHardware = (canAuthenticate != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE);

            JSObject ret = new JSObject();
            ret.put("isAvailable", isAvailable);
            ret.put("hasHardware", hasHardware);
            ret.put("code", canAuthenticate);
            call.resolve(ret);
        } catch (Exception e) {
            JSObject ret = new JSObject();
            ret.put("isAvailable", false);
            ret.put("hasHardware", false);
            ret.put("error", e.getMessage());
            call.resolve(ret);
        }
    }

    @PluginMethod
    public void authenticate(PluginCall call) {
        String title = call.getString("title", "خزنة — تأكيد البصمة");
        String subtitle = call.getString("subtitle", "المس مستشعر البصمة للمتابعة");
        String cancelText = call.getString("cancelText", "إلغاء");

        Activity rawActivity = getActivity();
        if (!(rawActivity instanceof FragmentActivity)) {
            call.reject("Activity unavailable", "NO_ACTIVITY");
            return;
        }
        FragmentActivity activity = (FragmentActivity) rawActivity;

        activity.runOnUiThread(() -> {
            try {
                Executor executor = ContextCompat.getMainExecutor(activity);

                BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                        .setTitle(title)
                        .setSubtitle(subtitle)
                        .setNegativeButtonText(cancelText)
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.BIOMETRIC_WEAK)
                        .build();

                BiometricPrompt prompt = new BiometricPrompt(activity, executor, new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                        call.reject(errString.toString(), String.valueOf(errorCode));
                    }

                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        JSObject ret = new JSObject();
                        ret.put("authenticated", true);
                        call.resolve(ret);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                    }
                });

                prompt.authenticate(promptInfo);
            } catch (Exception e) {
                call.reject("BiometricPrompt error: " + e.getMessage());
            }
        });
    }

    @PluginMethod
    public void setSecret(PluginCall call) {
        String key = call.getString("key");
        String secret = call.getString("secret");

        if (key == null || secret == null) {
            call.reject("Missing key or secret parameter");
            return;
        }

        byte[] plainBytes = null;
        try {
            SecretKey secretKey = recreateKey(key);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            plainBytes = secret.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = cipher.doFinal(plainBytes);

            String ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP);
            String encB64 = Base64.encodeToString(encrypted, Base64.NO_WRAP);

            SharedPreferences prefs = getContext().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            prefs.edit()
                .putString(key + "_iv", ivB64)
                .putString(key + "_data", encB64)
                .apply();

            JSObject ret = new JSObject();
            ret.put("success", true);
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Failed to set biometric secret: " + e.getMessage());
        } finally {
            if (plainBytes != null) {
                Arrays.fill(plainBytes, (byte) 0);
            }
        }
    }

    @PluginMethod
    public void getSecret(PluginCall call) {
        String key = call.getString("key");
        String title = call.getString("title", "خزنة — فتح بالبصمة");
        String subtitle = call.getString("subtitle", "المس مستشعر البصمة لفتح الخزنة");
        String cancelText = call.getString("cancelText", "كلمة المرور الرئيسية");

        if (key == null) {
            call.reject("Missing key parameter");
            return;
        }

        SharedPreferences prefs = getContext().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        String ivB64 = prefs.getString(key + "_iv", null);
        String encB64 = prefs.getString(key + "_data", null);

        if (ivB64 == null || encB64 == null) {
            call.reject("No secret found for key: " + key, "NOT_FOUND");
            return;
        }

        Activity rawActivity = getActivity();
        if (!(rawActivity instanceof FragmentActivity)) {
            call.reject("Activity unavailable", "NO_ACTIVITY");
            return;
        }
        FragmentActivity activity = (FragmentActivity) rawActivity;

        activity.runOnUiThread(() -> {
            try {
                Executor executor = ContextCompat.getMainExecutor(activity);

                BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                        .setTitle(title)
                        .setSubtitle(subtitle)
                        .setNegativeButtonText(cancelText)
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.BIOMETRIC_WEAK)
                        .build();

                BiometricPrompt prompt = new BiometricPrompt(activity, executor, new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                        call.reject(errString.toString(), String.valueOf(errorCode));
                    }

                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        byte[] decrypted = null;
                        try {
                            SecretKey secretKey = getKey(key);
                            if (secretKey == null) {
                                call.reject("Biometric key invalidated", "KEY_INVALIDATED");
                                return;
                            }
                            byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
                            byte[] encrypted = Base64.decode(encB64, Base64.NO_WRAP);

                            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
                            decrypted = cipher.doFinal(encrypted);

                            String secret = new String(decrypted, StandardCharsets.UTF_8);
                            JSObject ret = new JSObject();
                            ret.put("authenticated", true);
                            ret.put("secret", secret);
                            call.resolve(ret);
                        } catch (Exception e) {
                            call.reject("Decryption failed: " + e.getMessage(), "KEY_INVALIDATED");
                        } finally {
                            if (decrypted != null) {
                                Arrays.fill(decrypted, (byte) 0);
                            }
                        }
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                    }
                });

                prompt.authenticate(promptInfo);
            } catch (Exception e) {
                call.reject("Biometric prompt error: " + e.getMessage());
            }
        });
    }

    @PluginMethod
    public void deleteSecret(PluginCall call) {
        String key = call.getString("key");
        if (key != null) {
            SharedPreferences prefs = getContext().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            prefs.edit().remove(key + "_iv").remove(key + "_data").apply();
            try {
                KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
                keyStore.load(null);
                keyStore.deleteEntry(KEY_ALIAS_PREFIX + key);
            } catch (Exception ignored) {}
        }
        JSObject ret = new JSObject();
        ret.put("success", true);
        call.resolve(ret);
    }

    private SecretKey recreateKey(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        String alias = KEY_ALIAS_PREFIX + keyName;

        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
        }

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .build();

        keyGenerator.init(spec);
        return keyGenerator.generateKey();
    }

    private SecretKey getKey(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        String alias = KEY_ALIAS_PREFIX + keyName;
        if (!keyStore.containsAlias(alias)) {
            return null;
        }
        return (SecretKey) keyStore.getKey(alias, null);
    }
}
