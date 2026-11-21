/**
 * Setup Native Android Code for Khazna APK
 *
 * Injects:
 * 1. androidx.biometric dependency in app/build.gradle
 * 2. Monochrome vector drawable ic_khazna_tile.xml (for QS Tile & Notification)
 * 3. Real NativeBiometricPlugin (Android BiometricPrompt + AndroidKeyStore)
 * 4. KhaznaTileService (Quick Settings Tile in notification shade)
 * 5. MainActivity with FLAG_SECURE, quick access notification & overlay mode listener
 * 6. Permissions, allowBackup="false", adjustResize, and TileService in AndroidManifest.xml
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ANDROID_WRAPPER_DIR = path.resolve(__dirname, '..');
const CUSTOM_SRC_DIR = path.join(ANDROID_WRAPPER_DIR, 'custom-src');
const ANDROID_DIR = path.join(ANDROID_WRAPPER_DIR, 'android');
const APP_DIR = path.join(ANDROID_DIR, 'app');
const JAVA_DIR = path.join(APP_DIR, 'src', 'main', 'java', 'com', 'khazna', 'passwordmanager');
const DRAWABLE_DIR = path.join(APP_DIR, 'src', 'main', 'res', 'drawable');
const MANIFEST_PATH = path.join(APP_DIR, 'src', 'main', 'AndroidManifest.xml');
const BUILD_GRADLE_PATH = path.join(APP_DIR, 'build.gradle');

const TILE_VECTOR_XML = `<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FFFFFF"
        android:pathData="M12,2L4,5v6.09c0,5.05 3.41,9.76 8,10.91 4.59,-1.15 8,-5.86 8,-10.91V5l-8,-3zM12,11.99h7c-0.53,4.12 -3.28,7.79 -7,8.94V12H5V6.3l7,-3.11v8.8z" />
</vector>
`;

async function setup() {
  console.log('🚀 Setting up Khazna Native Android Features...');

  // Ensure Java package & drawable directories exist
  await fs.mkdir(JAVA_DIR, { recursive: true });
  await fs.mkdir(DRAWABLE_DIR, { recursive: true });

  // 1. Write monochrome shield icon for QS Tile & Notification
  const tileIconPath = path.join(DRAWABLE_DIR, 'ic_khazna_tile.xml');
  await fs.writeFile(tileIconPath, TILE_VECTOR_XML, 'utf8');
  console.log(`✓ Created monochrome tile icon -> ${tileIconPath}`);

  // 2. Copy Java source files
  const javaFiles = ['NativeBiometricPlugin.java', 'KhaznaTileService.java', 'MainActivity.java'];
  for (const file of javaFiles) {
    const src = path.join(CUSTOM_SRC_DIR, file);
    const dest = path.join(JAVA_DIR, file);
    await fs.copyFile(src, dest);
    console.log(`✓ Copied ${file} -> ${dest}`);
  }

  // 3. Update app/build.gradle with androidx.biometric
  if (await fileExists(BUILD_GRADLE_PATH)) {
    let gradle = await fs.readFile(BUILD_GRADLE_PATH, 'utf8');
    if (!gradle.includes('androidx.biometric:biometric')) {
      gradle = gradle.replace(
        /dependencies\s*\{/,
        "dependencies {\n    implementation 'androidx.biometric:biometric:1.1.0'"
      );
      await fs.writeFile(BUILD_GRADLE_PATH, gradle, 'utf8');
      console.log('✓ Added androidx.biometric:biometric:1.1.0 to app/build.gradle');
    }
  }

  // 4. Update AndroidManifest.xml with security flags, permissions & TileService
  if (await fileExists(MANIFEST_PATH)) {
    let manifest = await fs.readFile(MANIFEST_PATH, 'utf8');

    // Enforce android:allowBackup="false" so encrypted biometric prefs aren't uploaded to Android cloud backup
    if (manifest.includes('android:allowBackup="true"')) {
      manifest = manifest.replace('android:allowBackup="true"', 'android:allowBackup="false"');
      console.log('✓ Set android:allowBackup="false"');
    } else if (!manifest.includes('android:allowBackup=')) {
      manifest = manifest.replace('<application', '<application\n        android:allowBackup="false"');
    }

    // Ensure soft keyboard resizes WebView cleanly so password inputs are never covered
    if (!manifest.includes('android:windowSoftInputMode')) {
      manifest = manifest.replace(
        'android:name=".MainActivity"',
        'android:name=".MainActivity"\n            android:windowSoftInputMode="adjustResize"'
      );
    }

    // Add permissions
    const permissions = [
      '<uses-permission android:name="android.permission.USE_BIOMETRIC" />',
      '<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />',
    ];
    for (const perm of permissions) {
      if (!manifest.includes(perm)) {
        manifest = manifest.replace('</manifest>', `    ${perm}\n</manifest>`);
      }
    }

    // Add KhaznaTileService inside <application>
    const serviceTag = `
        <service
            android:name=".KhaznaTileService"
            android:icon="@drawable/ic_khazna_tile"
            android:label="خزنة سريعة"
            android:permission="android.permission.BIND_QUICK_SETTINGS_TILE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.service.quicksettings.action.QS_TILE" />
            </intent-filter>
        </service>`;

    if (!manifest.includes('KhaznaTileService')) {
      manifest = manifest.replace('</application>', `${serviceTag}\n    </application>`);
      console.log('✓ Added KhaznaTileService to AndroidManifest.xml');
    }

    await fs.writeFile(MANIFEST_PATH, manifest, 'utf8');
    console.log('✓ Updated AndroidManifest.xml');
  }

  console.log('🎉 Android Native Setup completed successfully!');
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

setup().catch((err) => {
  console.error('Setup error:', err);
  process.exit(1);
});
