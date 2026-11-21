import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.khazna.passwordmanager',
  appName: 'خزنة',
  webDir: 'www',  // Points to the PWA root (index.html)
  bundledWebRuntime: false,
  server: {
    // Use local files only — no remote server
    androidScheme: 'https',
    hostname: 'khazna.app',
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 0,
      backgroundColor: '#070b14',
    },
    StatusBar: {
      style: 'dark',
      backgroundColor: '#070b14',
    },
    BiometricAuth: {
      allowDeviceCredential: false,
    },
  },
  android: {
    buildOptions: {
      keystorePath: 'khazna-release.keystore',
      keystoreAlias: 'khazna',
    },
    minWebViewVersion: 95,
  },
};

export default config;
