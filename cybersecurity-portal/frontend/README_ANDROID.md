# SecureEye Android APK

This frontend is configured with Capacitor so the Vite React portal can be built as an Android app.

## Requirements

- Android Studio installed
- Android SDK installed, including SDK Platform 36
- `ANDROID_HOME` or `ANDROID_SDK_ROOT` pointing to the SDK folder
- Java 17

Typical Windows SDK path:

```text
C:\Users\<you>\AppData\Local\Android\Sdk
```

## Build APK

From the `frontend` folder:

```bash
npm install
npm run android:sync
cd android
gradlew.bat assembleDebug
```

The debug APK will be created at:

```text
frontend/android/app/build/outputs/apk/debug/app-debug.apk
```

## Open in Android Studio

```bash
npm run android:open
```

## Production Backend

Set `VITE_API_URL` before building if the APK should use a specific backend:

```bash
set VITE_API_URL=https://your-railway-backend.up.railway.app/api
npm run android:sync
```
