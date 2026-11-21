/**
 * Setup Native Android Code for Khazna APK
 *
 * Injects:
 * 1. androidx.biometric dependency in app/build.gradle
 * 2. Real NativeBiometricPlugin (Android BiometricPrompt + AndroidKeyStore)
 * 3. KhaznaTileService (Quick Settings Tile in notification shade)
 * 4. MainActivity with quick access notification and overlay mode listener
 * 5. Permissions and service in AndroidManifest.xml
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
const MANIFEST_PATH = path.join(APP_DIR, 'src', 'main', 'AndroidManifest.xml');
const BUILD_GRADLE_PATH = path.join(APP_DIR, 'build.gradle');

async function setup() {
  console.log('🚀 Setting up Khazna Native Android Features...');

  // Ensure Java package directory exists
  await fs.mkdir(JAVA_DIR, { recursive: true });

  // 1. Copy Java source files
  const javaFiles = ['NativeBiometricPlugin.java', 'KhaznaTileService.java', 'MainActivity.java'];
  for (const file of javaFiles) {
    const src = path.join(CUSTOM_SRC_DIR, file);
    const dest = path.join(JAVA_DIR, file);
    await fs.copyFile(src, dest);
    console.log(`✓ Copied ${file} -> ${dest}`);
  }

  // 2. Update app/build.gradle with androidx.biometric
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

  // 3. Update AndroidManifest.xml with permissions & TileService
  if (await fileExists(MANIFEST_PATH)) {
    let manifest = await fs.readFile(MANIFEST_PATH, 'utf8');

    // Add permissions
    const permissions = [
      '<uses-permission android:name="android.permission.USE_BIOMETRIC" />',
      '<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />',
    ];
    for (const perm of permissions) {
      if (!manifest.includes(perm)) {
        manifest = manifest.replace(
          '</manifest>',
          `    ${perm}\n</manifest>`
        );
      }
    }

    // Add KhaznaTileService inside <application>
    const serviceTag = `
        <service
            android:name=".KhaznaTileService"
            android:icon="@mipmap/ic_launcher"
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
