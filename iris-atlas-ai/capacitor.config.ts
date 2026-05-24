import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  /* ── App Identity ── */
  appId: 'com.yashchaudhary.irisatlas',
  appName: 'I.R.I.S ATLAS AI',

  /* ── Web assets (Vite build output) ── */
  webDir: 'dist',

  /* ── Android ── */
  android: {
    /* Minimum SDK 22 = Android 5.1 (broad device coverage) */
    minSdkVersion: 22,
    /* Target SDK 34 = Android 14 (Play Store requirement 2024+) */
    targetSdkVersion: 34,
    /* Compile SDK matching target */
    compileSdkVersion: 34,
    /* Allow cleartext traffic for local dev; HTTPS only in prod */
    allowMixedContent: false,
    /* Enable hardware back button */
    captureInput: true,
    /* WebView debugging in debug builds */
    webContentsDebuggingEnabled: true,
  },

  /* ── Plugins ── */
  plugins: {
    /* Status bar — dark content (white icons on dark bg) */
    StatusBar: {
      style: 'DARK',
      backgroundColor: '#05080f',
      overlaysWebView: false,
    },

    /* Splash screen — match app theme */
    SplashScreen: {
      launchShowDuration: 2000,
      launchAutoHide: true,
      backgroundColor: '#05080f',
      androidSplashResourceName: 'splash',
      androidScaleType: 'CENTER_CROP',
      showSpinner: false,
      splashFullScreen: true,
      splashImmersive: true,
    },

    /* Keyboard — resize body to avoid overlap */
    Keyboard: {
      resize: 'body',
      style: 'DARK',
      resizeOnFullScreen: true,
    },

    /* App (back button handling) */
    App: {},
  },

  /* ── Server (for live reload during development) ── */
  // Uncomment and set your machine IP for live reload on a real device:
  // server: {
  //   url: 'http://192.168.x.x:3000',
  //   cleartext: true,
  // },
};

export default config;
