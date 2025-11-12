# Analizden hariç tutulacak yaygın ve gürültüye neden olan sınıflar
STOP_CLASSES = frozenset([
    "Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/lang/StringBuilder;",
    "Ljava/lang/StringBuffer;", "Ljava/lang/Class;", "Ljava/lang/System;",
    "Ljava/util/ArrayList;", "Ljava/util/List;", "Ljava/util/Map;",
    "Ljava/util/HashMap;", "Ljava/util/HashSet;", "Ljava/util/Set;",
    "Ljava/util/Iterator;", "Ljava/util/Collection;", "Ljava/util/Arrays;",
    "Ljava/util/Collections;", "Ljava/util/Date;", "Ljava/util/Calendar;",
    "Ljava/lang/Exception;", "Ljava/lang/Throwable;", "Ljava/lang/Error;",
    "Ljava/lang/RuntimeException;", "Ljava/lang/Integer;", "Ljava/lang/Long;",
    "Ljava/lang/Float;", "Ljava/lang/Double;", "Ljava/lang/Boolean;",
    "Ljava/lang/Byte;", "Ljava/lang/Short;", "Ljava/lang/Character;",
    "Ljava/lang/Number;", "Ljava/lang/Math;", "Ljava/lang/Thread;",
    "Ljava/lang/Runnable;", "Ljava/io/Serializable;", "Ljava/io/IOException;",
    "Ljava/io/InputStream;", "Ljava/io/OutputStream;", "Ljava/io/Reader;",
    "Ljava/io/Writer;", "Ljava/io/BufferedReader;", "Ljava/io/BufferedWriter;",
    "Ljava/io/PrintWriter;", "Ljava/io/Closeable;",
    "Ljava/lang/annotation/Annotation;", "Ljava/lang/Enum;",
    "Ljava/text/SimpleDateFormat;", "Ljava/text/DateFormat;",
    "Landroid/os/Bundle;", "Landroid/os/Parcel;", "Landroid/os/Parcelable;",
    "Landroid/os/Handler;", "Landroid/os/Message;", "Landroid/os/Looper;",
    "Landroid/content/Context;", "Landroid/content/res/Resources;",
    "Landroid/content/res/Configuration;", "Landroid/util/Log;",
    "Landroid/util/DisplayMetrics;", "Landroid/util/TypedValue;",
    "Landroid/view/View;", "Landroid/view/ViewGroup;", "Landroid/view/LayoutInflater;",
    "Landroid/widget/TextView;", "Landroid/widget/Button;", "Landroid/widget/EditText;",
    "Landroid/widget/ImageView;", "Landroid/widget/LinearLayout;",
    "Landroid/widget/RelativeLayout;", "Landroid/widget/FrameLayout;",
    "Landroid/widget/Toast;", "Landroid/app/Activity;", "Landroid/app/Fragment;",
    "Landroid/app/Application;", "Landroid/app/Dialog;",
    "Landroidx/appcompat/app/AppCompatActivity;",
    "Landroidx/fragment/app/Fragment;", "Landroidx/fragment/app/FragmentActivity;",
    "Landroidx/recyclerview/widget/RecyclerView;",
    "Landroidx/viewpager/widget/ViewPager;",
    "Landroid/support/v7/app/AppCompatActivity;",
    "Landroid/support/v4/app/Fragment;", "Landroid/support/v4/app/FragmentActivity;",
    "Lcom/google/android/material/", "Landroidx/constraintlayout/",
    "Landroidx/lifecycle/", "Landroidx/core/",
    "Lcom/google/gson/", "Lorg/json/JSONObject;", "Lorg/json/JSONArray;",
    "Ljava/util/concurrent/", "Ljava/util/regex/Pattern;",
    "Landroid/graphics/Bitmap;", "Landroid/graphics/Canvas;",
    "Landroid/graphics/Paint;", "Landroid/graphics/Color;",
    "Landroid/graphics/drawable/Drawable;", "Landroid/text/TextUtils;",
    "Landroid/view/MotionEvent;", "Landroid/view/KeyEvent;",
    "Landroid/view/ViewTreeObserver;", "Landroid/animation/",
    "Lkotlin/jvm/internal/", "Lkotlin/Metadata;",
])

# Yüksek riskli ve doğrudan skoru etkileyen tehlikeli izinler
DANGEROUS_PERMISSIONS = frozenset([
    "SEND_SMS", "READ_SMS", "RECEIVE_SMS", "WRITE_SMS",
    "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS",
    "ANSWER_PHONE_CALLS", "READ_PHONE_NUMBERS",
    "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_NOTIFICATION_LISTENER_SERVICE",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "WRITE_SETTINGS", "WRITE_SECURE_SETTINGS",
    "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
    "DELETE_PACKAGES", "REQUEST_DELETE_PACKAGES", "QUERY_ALL_PACKAGES",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE", "MOUNT_UNMOUNT_FILESYSTEMS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "CAMERA", "RECORD_AUDIO", "BODY_SENSORS",
    "GET_ACCOUNTS", "READ_CONTACTS", "WRITE_CONTACTS", "AUTHENTICATE_ACCOUNTS",
    "CHANGE_NETWORK_STATE", "CHANGE_WIFI_STATE", "BLUETOOTH_ADMIN", "NFC",
    "BIND_VPN_SERVICE", "CAPTURE_AUDIO_OUTPUT", "MODIFY_PHONE_STATE",
    "RECEIVE_BOOT_COMPLETED", "WAKE_LOCK", "DISABLE_KEYGUARD", "READ_LOGS",
    "FOREGROUND_SERVICE", "REQUEST_COMPANION_RUN_IN_BACKGROUND",
    "REQUEST_COMPANION_USE_DATA_IN_BACKGROUND",
])

# API/Sınıf isimlerini anlamsal kategorilere eşleyen kurallar
CATEGORY_RULES = {
'benign_ui': (
    'Landroid/widget/',
    'Landroidx/recyclerview/widget/RecyclerView',
    'Landroidx/viewpager/widget/ViewPager',
    'Landroidx/appcompat/widget/Toolbar',
    'Lcom/google/android/material/',
    'Landroidx/constraintlayout/',
    'Landroid/view/Menu',
    'Landroid/widget/ImageView',
    'Landroid/widget/TextView',
    'onClick',
    'setContentView',
    'Landroidx/activity/ComponentActivity',
        'Landroidx/appcompat/app/ActionBar',
        'onCreate', 'onStart', 'onResume', 'onPause', 'onStop', 'onDestroy',
),
'sms': (
'Landroid/telephony/SmsManager;',
'Landroid/telephony/SmsMessage;',
'Landroid/provider/Telephony$Sms;',
'sendTextMessage',
'sendMultipartTextMessage',
'getDefault()Landroid/telephony/SmsManager;',
'sendDataMessage',
'sendTextMessageWithoutPersisting',
'Landroid/provider/Telephony$Mms;',
'SmsManager.sendMultipartTextMessage',
'SmsManager.injectSmsPdu',
'Landroid/telephony/SmsManager;->injectSmsPdu',
'createAppSpecificSmsToken',
'sendMultimediaMessage',
'Landroid/telephony/SmsManager;->createAppSpecificSmsToken',
),
'telephony': (
'Landroid/telephony/TelephonyManager;',
'Lcom/android/internal/telephony/ITelephony;',
'Landroid/telephony/PhoneStateListener;',
'Landroid/telephony/SubscriptionManager;',
'getDeviceId',
'getLine1Number',
'getSimSerialNumber',
'getSubscriberId',
'getNetworkOperator',
'getCellLocation',
'getSimOperatorName',
'getNetworkCountryIso',
'getCallState',
'getDataState',
'getNetworkType',
'listen(Landroid/telephony/PhoneStateListener;)',
'getAllCellInfo',
'getNeighboringCellInfo',
'getServiceState',
'getSimCountryIso',
'Landroid/telephony/TelephonyManager;->getAllCellInfo',
'endCall',
),
'crypto': (
'Ljavax/crypto/Cipher;',
'Ljavax/crypto/spec/SecretKeySpec;',
'Ljavax/crypto/spec/IvParameterSpec;',
'Ljava/security/MessageDigest;',
'Ljava/security/KeyStore;',
'Ljavax/crypto/Mac;',
'Ljava/security/SecureRandom;',
'AES',
'DES',
'RSA',
'SHA-256',
'MD5',
'doFinal',
'getInstance',
'CipherInputStream',
'CipherOutputStream',
'KeyGenerator',
'generateKey',
'PBEKeySpec',
'SecretKeyFactory',
'KeyAgreement',
'KeyPairGenerator',
'Ljavax/crypto/CipherInputStream;',
'Ljavax/crypto/CipherOutputStream;',
'init',
'update',
'Ljavax/crypto/KeyAgreement;',
'generateSecret',
'SHA-1',
'ECDH',
'javax/crypto/SecretKey',
'javax/crypto/SecretKeyFactory',
'javax/crypto/CipherOutputStream',
'javax/crypto/CipherInputStream',
),
'dynamic': (
'Ldalvik/system/DexClassLoader;',
'Ldalvik/system/PathClassLoader;',
'Ldalvik/system/BaseDexClassLoader;',
'Ljava/lang/reflect/Method;',
'Ljava/lang/System;->loadLibrary',
'Ljava/lang/Runtime;->exec',
'Ljava/lang/ProcessBuilder;',
'loadClass',
'loadDex',
'.dex',
'.jar',
'.apk',
'createPackageContext',
'getClassLoader',
'BaseDexClassLoader.defineClass',
'DexFile.loadDex',
'defineClass',
'definePackage',
'Ldalvik/system/DexFile;',
'optimize',
'loadDexFile',
'getDexClassLoader',
'defineClassN',
'Ljava/lang/Class;->forName',  # reflection-related loadClass patterns
'Ljava/lang/Runtime;->exec',
'Ljava/lang/Class;->forName',
    'Ljava/lang/Runtime;->exec',
    'invoke',
    'dalvik.system.VMStack',
),
'admin_operations': (
'Landroid/app/admin/DevicePolicyManager;',
'Landroid/app/admin/DeviceAdminReceiver;',
'lockNow',
'wipeData',
'resetPassword',
'setPasswordQuality',
'removeActiveAdmin',
'isAdminActive',
'setCameraDisabled',
'setKeyguardDisabled',
'setScreenCaptureDisabled',
'addUserRestriction',
'setLockTaskPackages',
'setGlobalProxy',
'setMaximumTimeToLock',
'setPasswordMinimumLength',
'getPasswordQuality',
'Landroid/app/admin/DevicePolicyManager;->setGlobalProxy',
),
'file_operations': (
'Ljava/io/FileInputStream;',
'Ljava/io/FileOutputStream;',
'Ljava/io/File;',
'Ljava/io/RandomAccessFile;',
'openFileOutput',
'openFileInput',
'/data/data/',
'/sdcard/',
'/mnt/',
'getExternalStorageDirectory',
'getFilesDir',
'deleteFile',
'mkdir',
'renameTo',
'Environment.getExternalStoragePublicDirectory',
'listFiles',
'FileChannel',
'FileWriter',
'FileReader',
'FileProvider',
'.nomedia',
'getCanonicalPath',
'createNewFile',
'setReadable',
'setWritable',
'Ljava/io/File;->createNewFile',
'getExternalFilesDir',
),
'location': (
'Landroid/location/LocationManager;',
'Landroid/location/Location;',
'Landroid/location/LocationListener;',
'Lcom/google/android/gms/location/',
'requestLocationUpdates',
'getLastKnownLocation',
'getLatitude',
'getLongitude',
'GPS_PROVIDER',
'NETWORK_PROVIDER',
'addGpsStatusListener',
'getBestProvider',
'isProviderEnabled',
'LocationServices',
'Lcom/google/android/gms/location/LocationServices;',
'Lcom/google/android/gms/location/FusedLocationProviderClient;',
        'FusedLocationProviderClient',
        'getLastLocation',
),
'camera_capture': (
    'Landroid/hardware/Camera;',
    'Landroid/hardware/camera2/',
    'takePicture',
    'setPreviewDisplay',
    'Landroid/hardware/Camera;->setPreviewCallback',
    # İzinlerden 'CAMERA'yı da buraya ekleyebiliriz (gerçi PERM_TO_CATEGORY'de var)
),
# YENİ KATEGORİ 2: Sadece Mikrofon/Ses
'microphone_capture': (
    'Landroid/media/MediaRecorder;',
    'Landroid/media/AudioRecord;',
    'startRecording',
    'setAudioSource',
    'setOutputFile',
    'prepare',
    'Landroid/media/MediaRecorder;->prepare',
    # İzinlerden 'RECORD_AUDIO'yu da buraya ekleyebiliriz
),
'root_detection': (
'/system/bin/su',
'/system/xbin/su',
'busybox',
'magisk',
'Superuser.apk',
'eu.chainfire.supersu',
'com.noshufou.android.su',
'com.topjohnwu.magisk',
'test-keys',
'/sbin/su',
'/system/bin/which su',
'com.koushikdutta.superuser',
'com.thirdparty.superuser',
'checkRootMethod',
'/data/local/xbin/su',
),
'background_ops': (
'Landroid/content/BroadcastReceiver;',
'Landroid/app/AlarmManager;',
'Landroid/app/Service;',
'Landroid/app/IntentService;',
'Landroid/app/job/JobScheduler;',
'Landroid/app/JobIntentService;',
'Landroidx/work/WorkManager;',
'setRepeating',
'setExact',
'onReceive',
'BOOT_COMPLETED',
'setInexactRepeating',
'cancel',
'onHandleWork',
'enqueueUniquePeriodicWork',
'Landroidx/work/WorkManager;->enqueueUniquePeriodicWork',
'Landroid/os/PowerManager$WakeLock;->acquire',
),
'device_info': (
'Landroid/os/Build;',
'Landroid/provider/Settings$Secure;',
'ANDROID_ID',
'getDeviceId',
'getSerialNumber',
'Build.MANUFACTURER',
'Build.MODEL',
'Build.VERSION',
'Build.FINGERPRINT',
'getSubscriberId',
'getMacAddress',
'Build.BOARD',
'Build.BOOTLOADER',
'Build.HARDWARE',
'getRadioVersion',
'getNetworkOperatorName',
),
'network': (
'Ljava/net/HttpURLConnection;',
'Ljava/net/URL;',
'Ljava/net/Socket;',
'Ljava/net/ServerSocket;',
'Lorg/apache/http/',
'Lokhttp3/',
'Landroid/net/ConnectivityManager;',
'Landroid/net/wifi/WifiManager;',
'Landroid/net/Uri;',
'openConnection',
'getInputStream',
'getOutputStream',
'setRequestMethod',
'SocketChannel',
'DatagramSocket',
'HttpClient',
'HttpsURLConnection',
'URLConnection.connect',
'SSLSocketFactory',
'TrustManager',
'HostnameVerifier',
'InetAddress.getByName',
'setDoOutput',
'setDoInput',
'setRequestProperty',
'connect',
'disconnect',
'Lokhttp3/Request$Builder;',
'POST',
'GET',
'User-Agent',
'Lokhttp3/OkHttpClient;',         # ekleme
'Lokhttp3/Request;',              # ekleme
'Lokhttp3/Response;',             # ekleme
'Lokhttp3/Interceptor;',          # ekleme
'Lretrofit2/Retrofit;',           # ekleme
'Lretrofit2/Call;',               # ekleme
'Lcom/android/volley/',                    # Volley networking
    'Lio/ktor/client/',                        # Ktor client
    'Landroidx/work/NetworkType',              # WorkManager network conditions
    'Lcom/github/nkzawa/socketio/',            # Socket.IO client
    'Lio/socket/client/Socket',                # Socket.IO
    'Lcom/squareup/okhttp3/websocket/',
    'Lcom/squareup/okhttp3/websocket/',
    'Lio/socket/client/Socket', 
    'Lorg/eclipse/paho/client/mqttv3/',
    'Ljava/net/Socket;->connect',  
),
'reflection': (
'Ljava/lang/Class;->forName',
'Ljava/lang/Class;->getDeclaredMethod',
'Ljava/lang/Class;->getMethod',
'Ljava/lang/reflect/Field;',
'Ljava/lang/reflect/Constructor;',
'invoke',
'setAccessible',
'newInstance',
'getDeclaredField',
'invokeExact',
'getDeclaredMethods',
'getDeclaredFields',
'Proxy.newProxyInstance',
'getConstructors',
'getDeclaredConstructors',
'Ljava/lang/reflect/Proxy;',
'newProxyInstance',
'Ljava/lang/Class;->getConstructors',
),
'obfuscation': (
'Landroid/util/Base64;',
'Base64.decode',
'Base64.encode',
'xor',
'unicode',
'\\u0',
'Ljava/lang/String;->getBytes',
'Ljava/lang/String;->toCharArray',
'Base64InputStream',
'StringBuilder.reverse',
'StringBuffer.reverse',
'URLEncoder.encode',
'InflaterInputStream',
'GZIPInputStream',
'AES/CBC/PKCS5Padding',
'rot13',
'hexEncode',
'decryptString',
'encryptString',
'Ljava/util/zip/InflaterInputStream;',
'control flow obfuscation',
),
'anti_debug': (
'Landroid/os/Debug;->isDebuggerConnected',
'Landroid/os/Debug;->waitingForDebugger',
'/proc/self/status',
'/proc/self/maps',
'TracerPid',
'ptrace',
'JDWP',
'android.os.Debug.waitingForDebugger',
'System.getenv("ro.debuggable")',
'SystemProperties.get("ro.build.type")',
'isEmulator',
'Build.TAGS.contains("test-keys")',
'android.os.SystemProperties.get',
'ro.debuggable',
'ro.secure',
'killProcess',
'exit',
'Landroid/os/Process;->myPid',
),
'native_code': (
'Ljava/lang/System;->loadLibrary',
'Ljava/lang/System;->load',
'.so',
'lib/',
'arm64-v8a',
'armeabi-v7a',
'x86',
'native',
'JNIEXPORT',
'JNIEnv',
'jstring',
'libart.so',
'nativeMethod',
),
'privileged_ops': (
'INSTALL_PACKAGES',
'DELETE_PACKAGES',
'READ_LOGS',
'MOUNT_UNMOUNT_FILESYSTEMS',
'WRITE_SECURE_SETTINGS',
'BIND_ACCESSIBILITY_SERVICE',
'CHANGE_CONFIGURATION',
'SYSTEM_ALERT_WINDOW',
'READ_FRAME_BUFFER',
'INJECT_EVENTS',
),
'banking_targets': (
'paypal',
'wallet',
'banking',
'bank',
'mastercard',
'visa',
'finance',
'payment',
'transaction',
'account',
'balance',
'transfer',
'iban',
'otp',
'pin',
'credentials',
'token',
'2fa',
'secureid',
'swift',
'credit card',
'debit card',
'cvv',
'expiration date',
'bitcoin wallet',
'cryptocurrency',
),
'modern_libs': (
'Landroidx/',
'Lcom/google/firebase/',
'Lcom/google/android/gms/',
'Lkotlin/',
'Lkotlinx/coroutines/',
'Lio/reactivex/',
'Lretrofit2/',
'Lcom/squareup/',
'Lcom/google/dagger/',
'Lcom/google/gson/',
'Lio/realm/',
'Lcom/airbnb/lottie/',
'Lcom/google/firebase/messaging/',
        'Lcom/google/firebase/analytics/',
        'Lcom/google/firebase/installations/',
        'Lcom/google/android/exoplayer2/',
        'Lcom/squareup/okhttp3/',
        'Lcom/squareup/retrofit2/',
        'Lcom/google/android/play/core/',          # App Bundle/Dynamic Features
    'Lcom/google/android/play/core/splitinstall/',
    'Lcom/google/android/play/core/review/',   # In-App Reviews
    'Lcom/google/android/play/core/appupdate/', # In-App Updates
    'Landroidx/biometric/',                    # Biometric auth
    'Landroidx/camera/core/',                  # CameraX
    'Landroidx/room/',                         # Room Database
    'Landroidx/navigation/',                   # Navigation component
    'Landroidx/paging/',                       # Paging library
    'Landroidx/security/crypto/',
    'Landroidx/security/crypto/',
    'Landroidx/compose/ui/', 
    'Lcom/google/mlkit/', 
    'Lcom/google/ar/core/',
    'Lio/ktor/', 
    'Lorg/koin/',
    'Lio/coil-kt/',
),
'accessibility': (
'Landroid/accessibilityservice/AccessibilityService;',
'Landroid/view/accessibility/AccessibilityEvent;',
'Landroid/view/accessibility/AccessibilityNodeInfo;',
'onAccessibilityEvent',
'performGlobalAction',
'getRootInActiveWindow',
'findAccessibilityNodeInfosByText',
'performAction',
'getText',
'findFocus',
'getWindow',
'TYPE_VIEW_CLICKED',
'TYPE_VIEW_TEXT_CHANGED',
'dispatchGesture',
'AccessibilityNodeInfo.ACTION_CLICK',
'getSource',
'recycle',
'Landroid/view/accessibility/AccessibilityNodeInfo;->recycle',
),
'notifications': (
'Landroid/service/notification/NotificationListenerService;',
'Landroid/app/Notification;',
'Landroid/app/NotificationManager;',
'onNotificationPosted',
'getActiveNotifications',
'cancelNotification',
'NotificationChannel',
'createNotificationChannel',
'deleteNotificationChannel',
'Landroid/app/NotificationManager;->createNotificationChannel',
'Landroidx/core/app/NotificationCompat;',
        'Landroidx/core/app/NotificationManagerCompat;',
        'NotificationCompat',
),
'webview': (
'Landroid/webkit/WebView;',
'Landroid/webkit/WebViewClient;',
'Landroid/webkit/JavascriptInterface;',
'addJavascriptInterface',
'loadUrl',
'evaluateJavascript',
'setWebViewClient',
'setWebChromeClient',
'shouldOverrideUrlLoading',
'loadDataWithBaseURL',
'setJavaScriptEnabled',
'postUrl',
'onPageFinished',
'onReceivedError',
'shouldInterceptRequest',
'Landroid/webkit/WebResourceRequest;',
'Landroid/webkit/WebSettings;',
        'setJavaScriptEnabled',
        'addJavascriptInterface'
),
'overlay': (
'Landroid/view/WindowManager;',
'Landroid/view/WindowManager$LayoutParams;',
'TYPE_SYSTEM_ALERT',
'TYPE_SYSTEM_OVERLAY',
'TYPE_APPLICATION_OVERLAY',
'addView',
'FLAG_NOT_FOCUSABLE',
'TYPE_ACCESSIBILITY_OVERLAY',
'updateViewLayout',
'removeView',
'FLAG_NOT_TOUCH_MODAL',
),
'keylogging': (
'Landroid/view/inputmethod/InputMethodService;',
'Landroid/inputmethodservice/Keyboard;',
'onKeyDown',
'onKeyUp',
'dispatchKeyEvent',
'setOnKeyListener',
'KeyEvent',
'getKeyCode',
'getCharacters',
'Landroid/view/KeyEvent;',
),
'screenshot': (
'Landroid/media/projection/MediaProjection;',
'Landroid/media/ImageReader;',
'Landroid/graphics/Bitmap;',
'getDrawingCache',
'createBitmap',
'createVirtualDisplay',
'acquireLatestImage',
'setSecure',
'Landroid/media/projection/MediaProjection;->createVirtualDisplay',
),
'clipboard': (
'Landroid/content/ClipboardManager;',
'Landroid/content/ClipData;',
'getPrimaryClip',
'setPrimaryClip',
'addPrimaryClipChangedListener',
'getText',
'hasText',
'getItemAt',
'Landroid/content/ClipData;->getItemAt',
),
'contacts': (
'Landroid/provider/ContactsContract;',
'Landroid/database/Cursor;',
'getContentResolver',
'query',
'CONTENT_URI',
'DISPLAY_NAME',
'PHONE_NUMBER',
'ContactsContract.CommonDataKinds.Email',
'ContactsContract.CommonDataKinds.Phone',
'insert',
'update',
),
'calendar': (
'Landroid/provider/CalendarContract;',
'CalendarContract.Events',
'CalendarContract.Calendars',
'CalendarContract.Reminders',
'CalendarContract.Attendees',
'queryEvents',
'insertEvent',
),
'shell_exec': (
'Ljava/lang/Runtime;->exec',
'Ljava/lang/ProcessBuilder;',
'su -c',
'sh',
'/system/bin/sh',
'pm install',
'pm uninstall',
'am start',
'getRuntime',
'process.waitFor',
'inputStream',
'outputStream',
'adb',
),
'vpn': (
'Landroid/net/VpnService;',
'Landroid/net/VpnService$Builder;',
'establish',
'protect',
'addAddress',
'addRoute',
'addDnsServer',
'setMtu',
'setUnderlyingNetworks',
'Landroid/net/VpnService$Builder;->addDnsServer',
),
'bluetooth': (
'Landroid/bluetooth/BluetoothAdapter;',
'Landroid/bluetooth/BluetoothDevice;',
'Landroid/bluetooth/BluetoothSocket;',
'getDefaultAdapter',
'getBondedDevices',
'startDiscovery',
'enable',
'disable',
'getRemoteDevice',
'createRfcommSocketToServiceRecord',
),
'nfc': (
'Landroid/nfc/NfcAdapter;',
'Landroid/nfc/Tag;',
'getDefaultAdapter',
'enableForegroundDispatch',
'disableForegroundDispatch',
'isEnabled',
'NdefMessage',
'Landroid/nfc/NdefMessage;',
),
'sensor': (
'Landroid/hardware/SensorManager;',
'Landroid/hardware/Sensor;',
'getDefaultSensor',
'registerListener',
'TYPE_ACCELEROMETER',
'TYPE_GYROSCOPE',
'TYPE_PROXIMITY',
'TYPE_LIGHT',
'SensorEvent',
'unregisterListener',
),
'account': (
'Landroid/accounts/AccountManager;',
'getAccounts',
'getAccountsByType',
'addAccountExplicitly',
'removeAccount',
'getPassword',
'getUserData',
'setAuthToken',
'blockingGetAuthToken',
),
'package_info': (
'Landroid/content/pm/PackageManager;',
'Landroid/content/pm/ApplicationInfo;',
'getInstalledPackages',
'getInstalledApplications',
'getPackageInfo',
'queryIntentActivities',
'getLaunchIntentForPackage',
'getPermissionInfo',
'checkPermission',
'Landroid/content/pm/PackageManager;->checkPermission',
),
'sqlite': (
'Landroid/database/sqlite/SQLiteDatabase;',
'Landroid/database/sqlite/SQLiteOpenHelper;',
'execSQL',
'rawQuery',
'insert',
'update',
'delete',
'setTransactionSuccessful',
'inTransaction',
'SQLiteStatement',
'execute',
'Landroidx/room/Database;',
    'Landroidx/room/Dao;',
    'Landroidx/room/Entity;',
    'Landroidx/room/Query;',
    'Lio/realm/RealmObject;',
    'Lio/objectbox/Box;',
    'Lio/realm/RealmObject;',
    'Lio/objectbox/Box;',
    'Landroidx/room/RoomDatabase;',
),
'analytics': (
    'Lcom/google/firebase/analytics/',
    'Lcom/google/android/gms/analytics/',
    'Lcom/flurry/android/',
    'Lcom/mixpanel/android/',
    'Lcom/amplitude/api/',
    'Lcom/crashlytics/android/Crashlytics;',
    'Lcom/google/firebase/crashlytics/',
    'Lcom/microsoft/appcenter/analytics/',
    'Lcom/segment/analytics/',
    'Lcom/newrelic/agent/android/',
    'Lcom/datadog/android/',
),
'shared_prefs': (
'Landroid/content/SharedPreferences;',
'getSharedPreferences',
'edit',
'putString',
'getString',
'commit',
'apply',
'putBoolean',
'getBoolean',
'clear',
'remove',
),
'content_provider': (
'Landroid/content/ContentProvider;',
'Landroid/content/ContentResolver;',
'query',
'insert',
'update',
'delete',
'openFile',
'getType',
'bulkInsert',
'notifyChange',
'registerContentObserver',
),
'intent_hijacking': (
'Landroid/content/Intent;',
'setComponent',
'getExtras',
'putExtra',
'startActivity',
'startService',
'sendBroadcast',
'addCategory',
'setData',
'setType',
'Intent.FLAG_GRANT_READ_URI_PERMISSION',
),
'classloader_manipulation': (
'Ljava/lang/ClassLoader;',
'getSystemClassLoader',
'getParent',
'findClass',
'defineClass',
'loadClass',
'getResource',
'findResource',
'Ljava/lang/ClassLoader;->loadClass',
),
'hooking_frameworks': (
'de.robv.android.xposed',
'XposedBridge',
'XposedHelpers',
'Lcom/elderdrivers/riru/edxp/',
'Lorg/lsposed/',
'frida',
'substrate',
'cydia',
'hook',
'methodHook',
'XC_MethodHook',
'findAndHookMethod',
'beforeHookedMethod',
'afterHookedMethod',
'com.saurik.substrate',
),
'emulator_detection': (
'goldfish',
'ranchu',
'vbox',
'ttVM_',
'andy',
'nox',
'bluestacks',
'generic',
'qemu',
'/proc/cpuinfo',
'Build.FINGERPRINT',
'Build.MODEL',
'Build.PRODUCT sdk_google_phone_armv7',
'Build.HARDWARE ranchu',
'emulator-5554',
'000000000000000',
),
'exfiltration': (
'MultipartEntityBuilder',
'DataOutputStream.write',
'OutputStreamWriter',
'FileInputStream.read',
'upload',
'postData',
'writeBytes',
'DataOutputStream.flush',
'setChunkedStreamingMode',
'multipart/form-data',
'base64Encode',
'compress',
'Lokhttp3/MultipartBody;',
),
'persistence': (
'RECEIVE_BOOT_COMPLETED',
'ACTION_BOOT_COMPLETED',
'AlarmManager.setRepeating',
'JobScheduler.schedule',
'BroadcastReceiver.onReceive',
'Service.onStartCommand',
'android.intent.action.BATTERY_CHANGED',
'android.intent.action.PACKAGE_ADDED',
'setExactAndAllowWhileIdle',
'ignoreBatteryOptimization',
),
'ui_injection': (
'LayoutInflater.inflate',
'WindowManager.addView',
'setContentView',
'AlertDialog.Builder',
'Toast.makeText',
'TYPE_APPLICATION_OVERLAY',
'ViewGroup.addView',
'setVisibility',
'bringToFront',
'phishing overlay',
),
'data_theft': (
'getContentResolver.query',
'ContactsContract.CommonDataKinds.Email',
'CallLog.Calls',
'SmsMessage.getMessageBody',
'FileInputStream',
'Browser.BOOKMARKS_URI',
'Telephony.Mms.CONTENT_URI',
'getInputStream',
'readBytes',
),
'anti_vm': (
'qemu',
'goldfish',
'ranchu',
'/proc/cpuinfo',
'Build.FINGERPRINT',
'Build.MODEL',
'Build.DEVICE generic',
'Build.USER android-build',
'ro.hardware qemu',
'init.svc.qemu-props',
),
'c2_communication': (
'beacon',
'heartbeat',
'command and control',
'C2',
'pollServer',
'registerDevice',
'sendCommand',
'http beacon',
),
'adware': (
'AdMob',
'AdView',
'loadAd',
'showInterstitial',
'Lcom/google/android/gms/ads/',
'ad click',
'impression',
),
'ransomware': (
'encryptFile',
'decryptFile',
'ransom note',
'pay bitcoin',
'file locked',
'your files are encrypted',
'your files are encrypted',
    'README_FOR_DECRYPT.txt', 
    '.locked',
    '.encrypted',
    'AES/CBC/PKCS5Padding',
),
'spyware': (
'trackUser',
'monitorActivity',
'sendLocation',
'logCalls',
'keylogger',
'screen record',
'logCalls',
    'keylogger',
    'screen record',
    'whatsapp/Databases', 
    'com.facebook.katana', 
    'com.facebook.orca',
    'getRunningAppProcesses',
),
'permission_abuse': (
'requestPermissions',
'onRequestPermissionsResult',
'dangerous permission',
'READ_SMS',
'WRITE_EXTERNAL_STORAGE',
'Landroid/app/Activity;->requestPermissions',
),
'payment_sdk': (
    'Lcom/stripe/android/',
    'Lcom/paypal/android/',
    'Lcom/braintreepayments/api/',
    'Lcom/adyen/checkout/',
    'com/google/android/gms/wallet/',
),
'permissions': (
    'Landroidx/core/app/ActivityCompat;',
    'Landroidx/core/content/ContextCompat;',
    'checkSelfPermission',
    'requestPermissions',
    'shouldShowRequestPermissionRationale',
    'onRequestPermissionsResult',
),
}


PERM_TO_CATEGORY = {
    "android.permission.READ_SMS": "sms",
    "android.permission.RECEIVE_SMS": "sms",
    "android.permission.SEND_SMS": "sms",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.WRITE_EXTERNAL_STORAGE": "file_operations",
    "android.permission.READ_EXTERNAL_STORAGE": "file_operations",
    "android.permission.INTERNET": "network",
    "android.permission.ACCESS_NETWORK_STATE": "network",
    "android.permission.WRITE_LOGS": "dangerous_permissions",

    'READ_SMS': 'sms', 'SEND_SMS': 'sms', 'RECEIVE_SMS': 'sms', 'WRITE_SMS': 'sms',
    'READ_PHONE_STATE': 'telephony', 'CALL_PHONE': 'telephony', 'READ_CALL_LOG': 'telephony',
    'WRITE_CALL_LOG': 'telephony', 'ADD_VOICEMAIL': 'telephony', 'USE_SIP': 'telephony',
    'PROCESS_OUTGOING_CALLS': 'telephony', 'ANSWER_PHONE_CALLS': 'telephony',
    'READ_PHONE_NUMBERS': 'telephony',
    'BIND_DEVICE_ADMIN': 'admin_operations', 'DEVICE_ADMIN': 'admin_operations',
    'WRITE_SETTINGS': 'admin_operations', 'WRITE_SECURE_SETTINGS': 'admin_operations',
    'READ_EXTERNAL_STORAGE': 'file_operations', 'WRITE_EXTERNAL_STORAGE': 'file_operations',
    'MANAGE_EXTERNAL_STORAGE': 'file_operations', 'MOUNT_UNMOUNT_FILESYSTEMS': 'file_operations',
    'ACCESS_FINE_LOCATION': 'location', 'ACCESS_COARSE_LOCATION': 'location',
    'ACCESS_BACKGROUND_LOCATION': 'location',
    'CAMERA': 'camera_capture', 'RECORD_AUDIO': 'microphone_capture', 'BODY_SENSORS': 'camera_capture',
    'RECEIVE_BOOT_COMPLETED': 'background_ops', 'WAKE_LOCK': 'background_ops',
    'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS': 'background_ops', 'FOREGROUND_SERVICE': 'background_ops',
    'REQUEST_COMPANION_RUN_IN_BACKGROUND': 'background_ops',
    'REQUEST_COMPANION_USE_DATA_IN_BACKGROUND': 'background_ops',
    'GET_ACCOUNTS': 'device_info', 'READ_CONTACTS': 'device_info', 'WRITE_CONTACTS': 'device_info',
    'AUTHENTICATE_ACCOUNTS': 'device_info',
    'SYSTEM_ALERT_WINDOW': 'overlay', 'DISABLE_KEYGUARD': 'overlay',
    'INSTALL_PACKAGES': 'privileged_ops', 'REQUEST_INSTALL_PACKAGES': 'privileged_ops',
    'DELETE_PACKAGES': 'privileged_ops', 'REQUEST_DELETE_PACKAGES': 'privileged_ops',
    'READ_LOGS': 'privileged_ops', 'QUERY_ALL_PACKAGES': 'privileged_ops',
    'BIND_ACCESSIBILITY_SERVICE': 'accessibility',
    'BIND_NOTIFICATION_LISTENER_SERVICE': 'notifications',
    'BIND_VPN_SERVICE': 'network', 'CHANGE_NETWORK_STATE': 'network',
    'CHANGE_WIFI_STATE': 'network', 'BLUETOOTH_ADMIN': 'network',
    'NFC': 'network',
    'CAPTURE_AUDIO_OUTPUT': 'microphone_capture', 'MODIFY_PHONE_STATE': 'telephony',
}


BENIGN_HINT_PERMS = frozenset([
    "USE_FINGERPRINT", "USE_BIOMETRIC", "BLUETOOTH", "NFC",
    "VIBRATE", "FLASHLIGHT", "ACCESS_NOTIFICATION_POLICY",
    "SET_WALLPAPER", "SET_WALLPAPER_HINTS", "EXPAND_STATUS_BAR",
    "KILL_BACKGROUND_PROCESSES", "REORDER_TASKS",
    "GET_PACKAGE_SIZE", "CHANGE_WIFI_MULTICAST_STATE",
    "ACCESS_WIFI_STATE", "ACCESS_NETWORK_STATE", "INTERNET",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "FOREGROUND_SERVICE",
    "POST_NOTIFICATIONS", "SCHEDULE_EXACT_ALARM",
    "USE_FULL_SCREEN_INTENT", "REQUEST_COMPANION_PROFILE_WATCH",
    "REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE",
    "ACTIVITY_RECOGNITION", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO", "ACCESS_MEDIA_LOCATION",
])

BENIGN_LIBRARIES = frozenset([
    'Landroidx/', 'Lcom/google/android/gms/', 'Lcom/google/firebase/',
    'Lokhttp3/', 'Lkotlin/', 'Lkotlinx/', 'Lcom/facebook/',
    'Lorg/json/', 'Lcom/google/gson/', 'Lcom/google/dagger/',
    'Lcom/squareup/retrofit2/', 'Lcom/squareup/picasso/', 'Lcom/squareup/okio/',
    'Lcom/squareup/moshi/', 'Lcom/squareup/leakcanary/',
    'Lcom/bumptech/glide/', 'Lio/reactivex/', 'Lorg/reactivestreams/',
    'Lcom/google/android/material/', 'Lcom/google/android/play/',
    'Lcom/google/common/', 'Lcom/google/protobuf/',
    'Lcom/airbnb/lottie/', 'Lcom/crashlytics/', 'Lio/fabric/',
    'Lorg/apache/commons/', 'Lorg/slf4j/', 'Lch/qos/logback/',
    'Lcom/jakewharton/', 'Lcom/android/volley/', 'Lcom/android/billingclient/',
    'Lcom/google/zxing/', 'Lcom/journeyapps/barcodescanner/',
    'Lde/hdodenhof/circleimageview/', 'Lcom/github/bumptech/',
    'Lcom/google/mlkit/', 'Lcom/google/ar/', 'Lcom/unity3d/',
    'Lcom/android/installreferrer/', 'Lcom/adjust/sdk/',
    'Lcom/appsflyer/', 'Lcom/mixpanel/android/', 'Lcom/amplitude/',
    'Lcom/segment/analytics/', 'Lcom/stripe/android/',
    'Lcom/paypal/android/', 'Lcom/braintreepayments/',
    'Lcom/twitter/sdk/', 'Lcom/linkedin/android/',
    'Lcom/microsoft/appcenter/', 'Lcom/amazonaws/',
    'Lio/grpc/', 'Lorg/greenrobot/eventbus/', 'Lcom/greenrobot/eventbus/',
    'Lcom/hannesdorfmann/mosby/', 'Lcom/arello_mobile/moxy/',
    'Lbutterknife/', 'Lcom/jakewharton/butterknife/',
    'Lcom/trello/rxlifecycle/', 'Lcom/uber/autodispose/',
    'Lcom/google/android/exoplayer2/', 'Lcom/google/android/datatransport/',
    'Lcom/android/support/', 'Landroid/support/v4/', 'Landroid/support/v7/',
    'Lcom/google/ads/', 'Lcom/google/android/ump/',
    'Lcom/facebook/ads/', 'Lcom/mopub/', 'Lcom/applovin/',
    'Lcom/unity3d/ads/', 'Lcom/vungle/', 'Lcom/chartboost/',
    'Lcom/inmobi/', 'Lcom/ironsource/', 'Lcom/tapjoy/','Lcom/stripe/android/',
    'Lcom/paypal/android/',
    'Lcom/braintreepayments/',
    'Lcom/twitter/sdk/',
    'Lcom/linkedin/android/',
    'Lcom/microsoft/appcenter/',
    'Lcom/amazonaws/',
    'Lio/grpc/',
    'Lorg/greenrobot/eventbus/',
    'Lcom/afollestad/material-dialogs/',
    'Lio/coil-kt/',
    'Lorg/koin/',
    'Lcom/google/android/flexbox/'
])

BENIGN_LIBRARIES_EXTRA = frozenset([
    'Landroidx/activity/', 'Landroidx/fragment/', 'Landroidx/lifecycle/',
    'Landroidx/room/', 'Landroidx/work/', 'Landroidx/navigation/',
    'Landroidx/recyclerview/', 'Landroidx/constraintlayout/', 'Landroidx/paging/',
    'Landroidx/databinding/', 'Landroidx/startup/', 'Landroidx/browser/',
    'Landroidx/security/', 'Landroidx/camera/', 'Landroidx/hilt/', 'Landroidx/compose/',
    'Ldagger/', 'Ldagger/hilt/', 'Lcom/google/dagger/hilt/',
    'Lorg/jsoup/', 'Lorg/simpleframework/xml/', 'Lcom/google/flatbuffers/', 'Lkotlinx/serialization/',
    'Lcom/squareup/okhttp/', 'Lcom/squareup/okhttp3/', 'Lio/reactivex/android/',
    'Lcom/facebook/fresco/', 'Ljp/wasabeef/glide/transformations/', 'Lcom/github/chrisbanes/photoview/',
    'Lcom/facebook/shimmer/', 'Lcom/airbnb/epoxy/',
    'Lcom/mapbox/mapboxsdk/', 'Lcom/google/maps/android/',
    'Lcom/huawei/hms/', 'Lcom/huawei/hms/ads/',
    'Lcom/adyen/', 'Lcom/squareup/reader/', 'Lcom/microsoft/identity/', 'Lcom/azure/', 'Lcom/google/android/gms/wallet/',
    'Lio/sentry/', 'Lcom/bugsnag/android/', 'Lcom/instabug/', 'Lcom/onesignal/',
    'Lcom/optimizely/', 'Lcom/launchdarkly/sdk/',
    'Lcom/bytedance/sdk/openadsdk/', 'Lcom/yandex/mobile/ads/', 'Lcom/mintegral/', 'Lcom/startapp/', 'Lcom/applovin/mediation/',
    'Lorg/tensorflow/lite/', 'Lcom/google/mediapipe/',
    'Lcom/google/tink/', 'Lorg/bouncycastle/', 'Lorg/brotli/dec/', 'Lcom/github/luben/zstd/',
    'Lcom/github/barteksc/pdfviewer/', 'Lcom/itextpdf/',
    'Lorg/apache/http/',
    'Lio/realm/',
])

BENIGN_LIBRARIES_ADDITIONAL = frozenset([
    # ===== Hybrid (Karma) ve Cross-Platform Frameworkler =====
    # Bu platformlarla yazılan uygulamaların temel paketleridir.
    'Lio/flutter/',                  # Flutter
    'Lcom/facebook/react/',          # React Native
    'Lorg/apache/cordova/',          # Cordova
    'Lcom/telerik/nativeandroid/',   # NativeScript
    'Lmono/android/',                # Xamarin/MAUI

    # ===== Test Kütüphaneleri =====
    # Genellikle son 'release' APK'da bulunmasalar da, analiz ettiğiniz set
    # debug/test build'leri içeriyorsa bunları 'benign' saymak önemlidir.
    'Ljunit/',
    'Lorg/junit/',
    'Lorg/mockito/',
    'Landroidx/test/',               # AndroidX Test kütüphaneleri (Espresso, Runner, vb.)
    'Lorg/robolectric/',             # Robolectric
    'Lio/mockk/',                    # MockK (Kotlin mocking kütüphanesi)
    'Lorg/hamcrest/',                # Hamcrest (Matcher kütüphanesi)

    # ===== Diğer Yaygın Java/Kotlin Yardımcı Kütüphaneleri =====
    'Lcom/google/guava/',            # Google Guava (Listenizde 'common' var ama 'guava' daha spesifik)
    'Lcom/fasterxml/jackson/',       # Jackson (JSON kütüphanesi, GSON/Moshi alternatifi)
    'Lorg/jetbrains/',               # JetBrains (Annotations vb. için)
    'Lio/objectbox/',                # ObjectBox (Alternatif bir veritabanı)

    # ===== Platforma Özel (WearOS, TV, Auto) =====
    'Landroidx/wear/',               # Wear OS
    'Landroidx/tv/',                 # Android TV
    'Landroidx/car/',                # Android Auto
    'Lcom/google/android/horologist/', # Wear OS için yardımcı kütüphane

    # ===== Kimlik Doğrulama (Authentication) SDK'ları =====
    'Lcom/auth0/android/',           # Auth0
    'Lcom/okta/android/',            # Okta
])

BENIGN_LIBRARIES_ADDITIONAL_V2 = frozenset([
    # ===== DI (Dependency Injection) - Hilt, Koin, Dagger =====
    'Ldagger/hilt/android/', 'Lcom/google/dagger/hilt/android/',
    'Lorg/koin/core/', 'Lorg/koin/android/',

    # ===== Serialization & JSON Alternatives =====
    'Lcom/fasterxml/jackson/core/',
    'Lcom/fasterxml/jackson/databind/',
    'Lkotlinx/serialization/json/',

    # ===== Networking (Advanced) =====
    'Lio/ktor/',                     # Ktor (Kotlin multiplatform HTTP client)
    'Lcom/squareup/retrofit2/converter/',

    # ===== Image Loading & Processing =====
    'Lcom/github/bumptech/glide/',
    'Lcoil/compose/', 'Lio/coil/kt/',

    # ===== Reactive Extensions (RxJava 3, Kotlin Flow) =====
    'Lio/reactivex/rxjava3/',
    'Lkotlinx/coroutines/',

    # ===== Logging =====
    'Lorg/slf4j/',
    'Ltimber/log/',                  # Timber (popüler Android logging)
    'Lcom/orhanobut/logger/',        # Logger

    # ===== Permissions & Runtime =====
    'Lcom/karumi/dexter/',           # Dexter (permissions)
    'Landroidx/permissions/',

    # ===== View Binding & Data Binding Helpers =====
    'Landroidx/databinding/',
    'Lcom/github/skydoves/binding/',

    # ===== Lottie & Animation =====
    'Lcom/airbnb/lottie/',

    # ===== Navigation & Deep Linking =====
    'Landroidx/navigation/safeargs/',

    # ===== Google Play Services (More Specific) =====
    'Lcom/google/android/gms/auth/',
    'Lcom/google/android/gms/location/',
    'Lcom/google/android/gms/maps/',
    'Lcom/google/android/gms/common/',
    'Lcom/google/android/gms/tasks/',

    # ===== Firebase (More Granular) =====
    'Lcom/google/firebase/auth/',
    'Lcom/google/firebase/firestore/',
    'Lcom/google/firebase/storage/',
    'Lcom/google/firebase/messaging/',
    'Lcom/google/firebase/analytics/',
    'Lcom/google/firebase/remoteconfig/',
    'Lcom/google/firebase/perf/',

    # ===== Huawei Mobile Services (HMS) =====
    'Lcom/huawei/hms/push/',
    'Lcom/huawei/hms/location/',
    'Lcom/huawei/hms/maps/',

    # ===== Analytics & Attribution (More) =====
    'Lcom/google/analytics/',
    'Lcom/crashlytics/android/',
    'Lio/sentry/android/',

    # ===== Ads (More Mediation & Networks) =====
    'Lcom/google/android/gms/ads/',
    'Lcom/facebook/ads/',
    'Lcom/mopub/mobileads/',
    'Lcom/applovin/sdk/',
    'Lcom/unity3d/services/ads/',

    # ===== Testing & Mocking (More) =====
    'Lorg/mockito/kotlin/',
    'Lcom/nhaarman/mockitokotlin2/',
    'Landroidx/arch/core/',

    # ===== Kotlin Stdlib & Extensions =====
    'Lkotlin/', 'Lkotlinx/', 'Lkotlin/jvm/',

    # ===== ProGuard / R8 / Shrinker Rules (Debug) =====
    'Lcom/android/tools/r8/',

    # ===== LeakCanary & Debugging Tools =====
    'Lcom/squareup/leakcanary/',

    # ===== ViewPager2, RecyclerView, CardView =====
    'Landroidx/viewpager2/',
    'Landroidx/cardview/',

    # ===== WorkManager, AlarmManager Alternatives =====
    'Landroidx/work/runtime/',

    # ===== Biometric & Security =====
    'Landroidx/biometric/',

    # ===== CameraX =====
    'Landroidx/camera/camera2/',

    # ===== ML Kit (More Specific) =====
    'Lcom/google/mlkit/vision/',

    # ===== ARCore =====
    'Lcom/google/ar/core/',

    # ===== Compose (More Specific) =====
    'Landroidx/compose/runtime/',
    'Landroidx/compose/ui/',
    'Landroidx/compose/material/',

    # ===== Accompanist (Compose Helpers) =====
    'Lcom/google/accompanist/',

    # ===== Hilt Worker, ViewModel =====
    'Ldagger/hilt/android/lifecycle/',

    # ===== Moshi & Kotlin Reflection =====
    'Lcom/squareup/moshi/kotlin/',

    # ===== Room (More Specific) =====
    'Landroidx/room/runtime/',
    'Landroidx/room/paging/',

    # ===== Paging 3 =====
    'Landroidx/paging/runtime/',

    # ===== EncryptedSharedPreferences =====
    'Landroidx/security/crypto/',

    # ===== ExoPlayer (More Specific) =====
    'Lcom/google/android/exoplayer2/ui/',
    'Lcom/google/android/exoplayer2/offline/',

    # ===== Datastore =====
    'Landroidx/datastore/',

    # ===== App Startup =====
    'Landroidx/startup/runtime/',

    # ===== Fragment =====
    'Landroidx/fragment/app/',

    # ===== Lifecycle (ViewModel, LiveData) =====
    'Landroidx/lifecycle/viewmodel/',
    'Landroidx/lifecycle/livedata/',

    # ===== Navigation Component =====
    'Landroidx/navigation/runtime/',

    # ===== ConstraintLayout =====
    'Landroidx/constraintlayout/core/',

    # ===== Shimmer, Lottie, Epoxy =====
    'Lcom/facebook/shimmer/',
    'Lcom/airbnb/epoxy/',

    # ===== Mapbox, Google Maps Android Utils =====
    'Lcom/mapbox/mapboxsdk/',
    'Lcom/google/maps/android/',

    # ===== OneSignal, Firebase Cloud Messaging =====
    'Lcom/onesignal/',

    # ===== AWS Amplify, Cognito =====
    'Lcom/amplifyframework/',

    # ===== Microsoft App Center (More) =====
    'Lcom/microsoft/appcenter/analytics/',
    'Lcom/microsoft/appcenter/crashes/',

    # ===== Stripe, PayPal, Braintree (More Specific) =====
    'Lcom/stripe/android/payments/',
    'Lcom/braintreepayments/api/',

    # ===== PDF & Document Viewers =====
    'Lcom/github/barteksc/androidpdfviewer/',

    # ===== Realm (MongoDB Realm) =====
    'Lio/realm/kotlin/',

    # ===== EventBus Alternatives =====
    'Lorg/greenrobot/eventbus/kotlin/',

    # ===== Otto (Legacy but still used) =====
    'Lcom/squareup/otto/',

    # ===== Gson TypeAdapter, etc. =====
    'Lcom/google/gson/internal/',

    # ===== OkHttp Interceptors (Common) =====
    'Lcom/squareup/okhttp3/logging/',

    # ===== Retrofit CallAdapter, Converter =====
    'Lcom/squareup/retrofit2/adapter/rxjava3/',

    # ===== Coroutines Test =====
    'Lorg/jetbrains/kotlinx/kotlinx-coroutines-test/',

    # ===== Truth (Google Testing) =====
    'Lcom/google/common/truth/',

    # ===== Espresso Contrib =====
    'Landroidx/test/espresso/contrib/',

    # ===== Turbine (Flow Testing) =====
    'Lapp/cash/turbine/',

    # ===== Stetho (Facebook Debug Bridge) =====
    'Lcom/facebook/stetho/',

    # ===== Flipper (Facebook Debug) =====
    'Lcom/facebook/flipper/',

    # ===== Chuck (OkHttp Interceptor UI) =====
    'Lcom/readystatesoftware/chuck/',

    # ===== Lynx (Android Debug) =====
    'Lcom/github/pedrovgs/lynx/',
])

BENIGN_LIBRARIES_ADDITIONAL_V3 = frozenset([
    # ===== Database & ORM =====
    'Lio/objectbox/',  # ObjectBox
    'Lio/realm/',  # Realm
    'Lcom/github/andrewoma/dex/',  # Dex
    'Lcom/raizlabs/android/dbflow/',  # DBFlow
    'Lcom/j256/ormlite/',  # ORMLite

    # ===== Async & Background Processing =====
    'Lcom/path/android/',  # Android Priority Job Queue
    'Landroidx/concurrent/',  # AndroidX Concurrent
    'Lcom/birbit/android/',  # Android Priority Job Queue

    # ===== UI Components & Custom Views =====
    'Lcom/google/android/flexbox/',  # Flexbox Layout
    'Lcom/github/rubensousa/',  # Various UI libraries
    'Lcom/ramotion/',  # RAMotion components
    'Lcom/tbuonomo/',  # Various view libraries
    'Lcom/romandanylyk/',  # Page Indicator
    'Lcom/booking/',  # RTL ViewPager

    # ===== Animation & Transitions =====
    'Lcom/transitionseverywhere/',  # Transitions Everywhere
    'Lcom/dawn/android/',  # Various animations
    'Lcom/github/florent37/',  # View animators

    # ===== Dependency Injection =====
    'Ltoothpick/',  # Toothpick DI
    'Ljavax/inject/',  # JSR-330

    # ===== Serialization & Parsing =====
    'Lcom/ryanharter/auto/value/',  # AutoValue
    'Lme/dm7/barcodescanner/',  # Barcode scanning
    'Lcom/google/zxing/',  # QR/Barcode processing

    # ===== Networking Enhancements =====
    'Lcom/facebook/stetho/',  # Stetho debug bridge
    'Lcom/facebook/flipper/',  # Flipper debugger
    'Lcom/jakewharton/picasso/',  # Picasso extensions
    'Lcom/squareup/tape/',  # Queue file

    # ===== Security & Cryptography =====
    'Lnet/openid/appauth/',  # OAuth2/OpenID
    'Lcom/auth0/',  # Auth0
    'Lcom/microsoft/identity/',  # MSAL

    # ===== Utility & Helper Libraries =====
    'Lcom/jakewharton/timber/',  # Timber logging
    'Lcom/orhanobut/logger/',  # Logger
    'Lcom/github/ajalt/',  # Various utilities

    # ===== Testing & Debugging =====
    'Landroidx/benchmark/',  # Benchmarking
    'Lcom/facebook/screenshot/',  # Screenshot tests
    'Lcom/karumi/',  # Various test helpers

    # ===== Architecture Components =====
    'Landroidx/lifecycle/extensions/',
    'Landroidx/savedstate/',
    'Landroidx/loader/',

    # ===== Google Play & Billing =====
    'Lcom/android/billingclient/api/',
    'Lcom/google/android/play/core/',

    # ===== Push Notifications =====
    'Lcom/urbanairship/',  # Urban Airship
    'Lcom/onesignal/',  # OneSignal
    'Lcom/pusher/',  # Pusher

    # ===== Analytics & Monitoring =====
    'Lcom/newrelic/',  # New Relic
    'Lcom/datadog/',  # Datadog
    'Lcom/splunk/',  # Splunk

    # ===== Maps & Location Services =====
    'Lcom/mapbox/',  # Mapbox
    'Lorg/osmdroid/',  # OpenStreetMap
    'Lcom/google/maps/',  # Google Maps Web API

    # ===== Media & Image Processing =====
    'Lcom/yalantis/',  # UCrop & other image tools
    'Lcom/davemorrissey/',  # Subsampling Scale Image View
    'Lcom/github/chrisbanes/',  # PhotoView

    # ===== Payment Processors =====
    'Lcom/adyen/',  # Adyen
    'Lcom/braintree/',  # Braintree
    'Lcom/stripe/stripeandroid/',

    # ===== Social Media Integration =====
    'Lcom/facebook/',  # Facebook SDK
    'Lcom/twitter/',  # Twitter SDK
    'Lcom/linkedin/',  # LinkedIn SDK

    # ===== Cross-Platform Frameworks =====
    'Lorg/apache/cordova/',  # Cordova/PhoneGap
    'Lio/flutter/plugins/',  # Flutter plugins
    'Lcom/getcapacitor/',  # Capacitor

    # ===== Build Tools & Gradle Plugins =====
    'Lcom/android/tools/build/',  # Android build tools
    'Lorg/gradle/',  # Gradle
    'Lcom/google/devtools/',  # Various Google tools
])

BENIGN_LIBRARIES_ADDITIONAL_V4 = frozenset([
    # ===== Material Design & UI Components =====
    'Lcom/google/android/material/textfield/',
    'Lcom/google/android/material/button/',
    'Lcom/google/android/material/bottomsheet/',
    'Lcom/google/android/material/snackbar/',
    'Lcom/google/android/material/dialog/',
    'Lme/zhanghai/android/materialprogressbar/',
    'Lcom/afollestad/materialdialogs/',

    # ===== Image & Media Libraries =====
    'Lcom/github/bumptech/glide/load/',
    'Lcom/github/bumptech/glide/request/',
    'Lcom/nostra13/universalimageloader/',  # Universal Image Loader
    'Lcom/facebook/drawee/',  # Fresco Drawee
    'Lcom/squareup/picasso2/',
    'Lcom/caverock/androidsvg/',  # SVG support
    'Lpl/droidsonroids/gif/',  # GIF support

    # ===== Reactive Programming =====
    'Lio/reactivex/rxjava2/',
    'Lio/reactivex/subjects/',
    'Lio/reactivex/disposables/',
    'Lio/reactivex/schedulers/',
    'Lcom/jakewharton/rxbinding/',
    'Lcom/jakewharton/rxrelay/',

    # ===== Networking & HTTP =====
    'Lorg/apache/http/client/',
    'Lorg/apache/http/impl/',
    'Lretrofit2/',
    'Lokhttp3/internal/',
    'Lokio/',
    'Lcom/squareup/okhttp/internal/',

    # ===== JSON & XML Processing =====
    'Lorg/json/simple/',
    'Lcom/google/gson/annotations/',
    'Lcom/google/gson/stream/',
    'Lcom/fasterxml/jackson/annotation/',
    'Lorg/simpleframework/',
    'Lorg/xmlpull/',

    # ===== Dependency Injection (More) =====
    'Ljavax/inject/Provider/',
    'Lcom/google/inject/',  # Guice
    'Ltoothpick/config/',

    # ===== Annotations & Code Generation =====
    'Lcom/google/auto/value/',
    'Lcom/google/auto/factory/',
    'Lcom/squareup/javapoet/',
    'Lcom/squareup/kotlinpoet/',
    'Lorg/jetbrains/annotations/',
    'Landroidx/annotation/',

    # ===== Coroutines & Flow =====
    'Lkotlinx/coroutines/flow/',
    'Lkotlinx/coroutines/channels/',
    'Lkotlinx/coroutines/android/',

    # ===== Storage & Preferences =====
    'Landroidx/preference/',
    'Lcom/chibatching/kotpref/',  # Kotlin preferences
    'Lcom/orhanobut/hawk/',  # Secure storage
    'Lcom/github/pwittchen/reactivenetwork/',

    # ===== Permissions Management =====
    'Lcom/karumi/dexter/',
    'Lcom/github/permissions/',
    'Lpub/devrel/easypermissions/',

    # ===== Date & Time =====
    'Lorg/joda/time/',  # Joda Time
    'Lnet/danlew/android/joda/',
    'Lorg/threeten/',  # ThreeTen (JSR-310 backport)

    # ===== Background Processing =====
    'Lcom/evernote/android/job/',  # Android Job
    'Lcom/firebase/jobdispatcher/',
    'Landroidx/work/impl/',

    # ===== WebView & Browser =====
    'Landroidx/webkit/',
    'Lorg/chromium/',
    'Lcom/google/androidbrowserhelper/',

    # ===== ViewPager & Indicators =====
    'Lcom/viewpagerindicator/',
    'Lme/relex/',  # CircleIndicator
    'Lcom/rd/animation/',  # Page indicator

    # ===== RecyclerView Extensions =====
    'Lcom/mikepenz/fastadapter/',
    'Leu/davidea/flexibleadapter/',
    'Lcom/h6ah4i/android/widget/advrecyclerview/',

    # ===== Charts & Graphs =====
    'Lcom/github/mikephil/charting/',  # MPAndroidChart
    'Lcom/github/aachartmodel/',
    'Lim/dacer/androidcharts/',

    # ===== QR & Barcode =====
    'Lcom/journeyapps/barcodescanner/camera/',
    'Lcom/google/zxing/client/',
    'Lme/dm7/barcodescanner/zxing/',

    # ===== Camera & Video =====
    'Lcom/otaliastudios/cameraview/',
    'Lcom/google/android/cameraview/',
    'Landroidx/camera/core/',
    'Landroidx/camera/lifecycle/',

    # ===== Location & Maps =====
    'Lcom/google/android/gms/location/places/',
    'Lcom/google/maps/android/clustering/',
    'Lcom/google/maps/android/heatmaps/',

    # ===== Social Sharing =====
    'Lcom/sharethrough/',
    'Lcom/tumblr/',
    'Lcom/pinterest/',

    # ===== Crash Reporting (More) =====
    'Lcom/crashlytics/sdk/',
    'Lio/sentry/core/',
    'Lcom/microsoft/appcenter/crashes/',
    'Lacra/sender/',  # ACRA

    # ===== A/B Testing & Feature Flags =====
    'Lcom/optimizely/ab/',
    'Lcom/launchdarkly/',
    'Lcom/google/firebase/abt/',

    # ===== In-App Purchases =====
    'Lcom/android/vending/billing/',
    'Lcom/google/android/play/core/appupdate/',
    'Lcom/google/android/play/core/review/',

    # ===== Ads Mediation =====
    'Lcom/google/ads/mediation/',
    'Lcom/facebook/ads/internal/',
    'Lcom/applovin/mediation/adapters/',
    'Lcom/google/android/gms/ads/mediation/',

    # ===== Logging Frameworks =====
    'Lorg/apache/log4j/',
    'Lch/qos/logback/classic/',
    'Lcom/jakewharton/timber/log/',

    # ===== Validation & Forms =====
    'Lcom/mobsandgeeks/saripaar/',  # Android Saripaar
    'Lbr/com/ilhasoft/support/validation/',

    # ===== Keyboard & Input =====
    'Lnet/yslibrary/android/keyboardvisibilityevent/',
    'Lcom/github/javiersantos/',

    # ===== Swipe & Gesture =====
    'Lcom/daimajia/swipe/',
    'Lcom/daimajia/androidanimations/',
    'Lcom/github/nisrulz/sensey/',

    # ===== Markdown & Rich Text =====
    'Lio/noties/markwon/',
    'Lru/noties/markwon/',
    'Lcom/commonsware/cwac/richedit/',

    # ===== File Operations =====
    'Lcom/nononsenseapps/filepicker/',
    'Lcom/github/angads25/filepicker/',
    'Landroidx/documentfile/',

    # ===== Bluetooth & NFC =====
    'Lcom/polidea/rxandroidble/',
    'Lno/nordicsemi/android/ble/',
    'Landroidx/nfc/',

    # ===== Kotlin Extensions =====
    'Lorg/jetbrains/kotlin/android/',
    'Lkotlin/collections/',
    'Lkotlin/sequences/',
    'Lkotlin/text/',

    # ===== AndroidX Core =====
    'Landroidx/core/app/',
    'Landroidx/core/content/',
    'Landroidx/core/graphics/',
    'Landroidx/core/util/',
    'Landroidx/core/view/',

    # ===== AppCompat =====
    'Landroidx/appcompat/app/',
    'Landroidx/appcompat/widget/',
    'Landroidx/appcompat/view/',

    # ===== Architecture Components (More) =====
    'Landroidx/lifecycle/process/',
    'Landroidx/lifecycle/service/',
    'Landroidx/arch/core/executor/',

    # ===== Palette & Colors =====
    'Landroidx/palette/',
    'Lcom/github/QuadFlask/colorpicker/',

    # ===== Transitions & Animations =====
    'Landroidx/transition/',
    'Lcom/github/florent37/viewanimator/',

    # ===== Shimmer & Loading Effects =====
    'Lcom/facebook/shimmer/shimmer/',
    'Lcom/ethanhua/skeleton/',

    # ===== Bottom Navigation & Tabs =====
    'Lcom/google/android/material/tabs/',
    'Lcom/google/android/material/bottomnavigation/',
    'Lcom/aurelhubert/ahbottomnavigation/',

    # ===== Emoji & Stickers =====
    'Landroidx/emoji/',
    'Lio/github/vanpra/emoji/',

    # ===== Video Players =====
    'Lcom/google/android/exoplayer2/source/',
    'Lcom/google/android/exoplayer2/extractor/',
    'Lcom/google/android/exoplayer2/upstream/',

    # ===== PDF Rendering =====
    'Landroid/graphics/pdf/',
    'Lcom/tom_roush/pdfbox/',

    # ===== Encryption & Hashing =====
    'Ljavax/crypto/',
    'Ljava/security/',
    'Lorg/spongycastle/',  # SpongyCastle (Android BC fork)

    # ===== Utilities =====
    'Lorg/apache/commons/lang/',
    'Lorg/apache/commons/io/',
    'Lorg/apache/commons/codec/',
    'Lorg/apache/commons/collections/',

    # ===== Kotlin Standard Library =====
    'Lkotlin/io/',
    'Lkotlin/random/',
    'Lkotlin/ranges/',
    'Lkotlin/jvm/functions/',
    'Lkotlin/jvm/internal/',

    # ===== Accompanist (Compose) =====
    'Lcom/google/accompanist/permissions/',
    'Lcom/google/accompanist/navigation/',
    'Lcom/google/accompanist/pager/',
    'Lcom/google/accompanist/systemuicontroller/',

    # ===== Compose UI (More) =====
    'Landroidx/compose/foundation/',
    'Landroidx/compose/animation/',
    'Landroidx/compose/material3/',

    # ===== WorkManager (More) =====
    'Landroidx/work/multiprocess/',

    # ===== Splash Screen API =====
    'Landroidx/core/splashscreen/',

    # ===== Window Manager =====
    'Landroidx/window/',

    # ===== Media3 (ExoPlayer successor) =====
    'Landroidx/media3/',
])

BENIGN_LIBRARIES_ADDITIONAL_V5 = frozenset([
    # Google Android genel alt paketleri
    'Lcom/google/android/',

    # Netty (Java networking framework)
    'Lio/netty/',
    'Lio/netty/handler/',
    'Lio/netty/util/',
    'Lio/netty/channel/',
    'Lio/netty/buffer/',

    # Java 8+ desugar stream API (benign, toolchain kaynaklı)
    'Lj$/util/stream/',
    'Lj$/util/concurrent/',
    'Ljava/util/concurrent/',
    'Ljava/util/function/',

    # Java 8+ desugar time API
    'Lj$/time/',
    'Lj$/time/chrono/',
    'Lj$/time/format/',

    # Android SDK core benign paketleri
    'Landroid/graphics/drawable/',

    # Diğer benign kütüphaneler
    'Lme/zhanghai/android/',
])

BENIGN_LIBRARIES_ADDITIONAL_V6 = frozenset([
    'Lcom/google/android/',
    'Lio/netty/',
    'Lj$/util/stream/',
    'Lj$/time/',
    'Landroid/graphics/drawable/',
    'Ljava/util/concurrent/',
    'Lcom/unity3d/',
    'Lcom/squareup/okhttp/',
    'Lcom/squareup/retrofit2/',
    'Lorg/xmlpull/',
    'Ljavax/net/ssl/',
    'Lcom/google/android/exoplayer2/',
    'Lcom/google/ads/',
    'Lorg/apache/commons/',
])

BENIGN_LIBRARIES_ADDITIONAL_V7 = frozenset([
    'Lcom/geka000/digitron/',      # App-specific benign package (optional)
    'Ljava/util/concurrent/',      # Core Java concurrency
    'Lj$/time/chrono/',            # Java desugar time
    'Lj$/time/format/',            # Java desugar time format
    'Lj$/time/temporal/',          # Java desugar temporal API
    'Landroid/graphics/drawable/', # Android SDK
    'Landroid/view/inputmethod/',  # Keyboard / input handling (benign)
    'Landroid/text/style/',        # Text styling (benign)
    'Ljava/lang/reflect/',         # Java reflection API (benign, common)
    'Landroid/content/pm/',        # PackageManager (benign usage)
    'Landroid/view/accessibility/',# Android accessibility API
    'Ljava/util/zip/',             # ZIP/Deflate (benign compression)
    'Lj$/time/zone/',              # Java desugar time zones
    'Ljavax/net/ssl/',             # SSL networking
    'Landroid/database/sqlite/',   # Local database (benign)
])

BENIGN_LIBRARIES_ADDITIONAL_V8 = frozenset([
    'Lcom/yandex/mobile/',
    'Lio/appmetrica/analytics/',
    'Lorg/bouncycastle/jcajce/',
    'Lcom/my/target/',
    'Lcom/my/tracker/',
    'Lcom/monetization/ads/',
    'Lorg/bouncycastle/jce/',
    'Lcom/iab/omid/',
    'Ljava/util/concurrent/',
    'Lio/ktor/utils/',
    'Ljava/security/cert/',
    'Lorg/bouncycastle/crypto/',
    'Lcom/yandex/varioqub/',
    'Landroid/graphics/drawable/',
    'Ljava/security/spec/',
])

BENIGN_LIBRARIES_ADDITIONAL_V9 = frozenset([
    'Lcom/revenuecat/purchases/',
    'Lcom/google/android/',
    'Ljava/util/concurrent/',
    'Lone4studio/wallpaper/one4wall/',
    'Landroid/graphics/drawable/',
    'Landroid/text/style/',
    'Lcom/onesignal/shortcutbadger/',
    'Ljava/lang/reflect/',
    'Landroid/content/pm/',
    'Ljava/util/zip/',
    'Landroid/view/accessibility/',
    'Landroid/view/animation/',
    'Ljavax/net/ssl/',
    'Landroid/view/inputmethod/',
    'Landroid/app/job/',
])

BENIGN_LIBRARIES_ADDITIONAL_V10 = frozenset([
    'Lcom/google/mlkit/vision/',
    'Lcom/google/mlkit/common/',
    'Lcom/google/mlkit/translate/',
    'Lcom/google/mlkit/nl/',
    'Lcom/google/mlkit/text/',
    'Lcom/google/mlkit/image/',
    'Lcom/google/android/gms/ads/',
    'Lcom/google/android/gms/vision/',
    'Lcom/google/android/gms/location/',
    'Lcom/google/android/gms/maps/',
    'Lcom/google/android/gms/common/',
    'Lcom/google/android/gms/auth/',
    'Lcom/google/android/gms/tasks/',
    'Lcom/google/android/exoplayer2/',
    'Lcom/google/android/exoplayer2/ui/',
    'Lcom/google/android/exoplayer2/offline/',
    'Landroidx/camera/core/',
    'Landroidx/camera/lifecycle/',
    'Landroidx/camera/view/',
    'Landroidx/camera/video/',
    'Landroidx/camera/extensions/',
    'Lcom/google/tflite/support/',
    'Lorg/tensorflow/lite/task/',
    'Lorg/tensorflow/lite/examples/',
    'Lorg/tensorflow/lite/support/',
    'Lcom/google/mediapipe/',
    'Lcom/google/mediapipe/framework/',
    'Lcom/google/mediapipe/tasks/',
    'Lcom/google/mediapipe/solutions/',
    'Lcom/github/barteksc/pdfviewer/',
    'Lcom/itextpdf/text/',
    'Lcom/itextpdf/kernel/',
    'Landroidx/core/app/',
    'Landroidx/core/content/',
    'Landroidx/core/view/',
    'Landroidx/core/widget/',
    'Landroidx/lifecycle/viewmodel/',
    'Landroidx/lifecycle/livedata/',
    'Landroidx/datastore/preferences/',
    'Landroidx/security/crypto/',
    'Landroidx/work/impl/',
    'Landroidx/work/runtime/',
    'Landroidx/startup/runtime/',
    'Lcom/onesignal/',
    'Lcom/facebook/shimmer/',
    'Lcom/airbnb/epoxy/',
    'Lcom/yandex/metrica/',
    'Lio/appmetrica/analytics/',
    'Lcom/bumptech/glide/',
    'Lio/reactivex/',
    'Lio/reactivex/rxjava3/',
    'Lkotlinx/coroutines/',
    'Ljava/util/concurrent/',
    'Landroid/app/job/',
    'Ljavax/net/ssl/',
    'Ljava/security/spec/',
])

BENIGN_LIBRARIES_ADDITIONAL_V11 = frozenset([
    'Lcom/mapbox/maps/',
    'Lcom/mapbox/common/',
    'Lcom/mapbox/android/',
    'Lcom/mapbox/geojson/',
    'Lcom/mapbox/turf/',
    'Lcom/mapbox/api/',
    'Lcom/mapbox/annotations/',
    'Lcom/mapbox/navigation/',
    'Lcom/mapbox/gestures/',
    'Lcom/mapbox/plugins/',
    'Lcom/mapbox/android/telemetry/',
    'Lcom/mapbox/core/',
    'Lcom/mapbox/extensions/',
    'Lcom/google/android/libraries/places/',
    'Lcom/google/android/libraries/maps/',
    'Lcom/google/maps/utils/',
    'Lcom/google/maps/android/data/',
    'Lcom/google/maps/android/ui/',
    'Lcom/google/maps/android/clustering/',
    'Lcom/google/maps/android/heatmaps/',
    'Landroidx/core/location/',
    'Landroidx/lifecycle/service/',
    'Landroidx/lifecycle/runtime/',
    'Landroidx/lifecycle/process/',
    'Landroidx/work/',
    'Landroidx/work/impl/',
    'Landroidx/work/runtime/',
    'Landroidx/startup/',
    'Landroidx/appcompat/',
    'Landroidx/core/app/',
    'Landroidx/core/content/',
    'Landroidx/core/util/',
    'Landroidx/core/view/',
    'Landroidx/annotation/',
    'Landroidx/constraintlayout/',
    'Landroidx/fragment/',
    'Landroidx/lifecycle/viewmodel/',
    'Landroidx/lifecycle/livedata/',
    'Landroidx/lifecycle/viewmodel/ktx/',
    'Landroidx/navigation/',
    'Landroidx/room/',
    'Landroidx/recyclerview/',
    'Landroidx/datastore/',
    'Landroidx/work/coroutines/',
    'Landroidx/datastore/preferences/',
    'Landroidx/security/',
    'Landroidx/security/crypto/',
    'Lcom/squareup/okio/',
    'Lcom/squareup/moshi/',
    'Lcom/squareup/okhttp3/',
    'Lcom/squareup/retrofit2/',
    'Lcom/squareup/retrofit2/converter/',
    'Lkotlinx/coroutines/',
    'Lkotlinx/serialization/',
    'Lkotlinx/serialization/json/',
    'Lkotlin/jvm/',
    'Ljava/util/concurrent/',
    'Ljavax/net/ssl/',
    'Ljava/security/cert/',
    'Lorg/json/',
])


BENIGN_LIBRARIES = frozenset(
    set(BENIGN_LIBRARIES) |
    set(BENIGN_LIBRARIES_EXTRA) |
    set(BENIGN_LIBRARIES_ADDITIONAL) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V2) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V3) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V4) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V5) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V6) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V7) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V8) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V9) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V10) |
    set(BENIGN_LIBRARIES_ADDITIONAL_V11)
)

BENIGN_LIBRARY_WEIGHTS = {
    'Lcom/google/ads/': 3.0,
    'Lcom/facebook/ads/': 3.0,
    'Lcom/mopub/': 3.0,
    'Lcom/applovin/': 3.0,
    'Lcom/unity3d/ads/': 3.0,
    'Lcom/adjust/sdk/': 2.5,
    'Lcom/appsflyer/': 2.5,
    'Lcom/mixpanel/android/': 2.5,      # EKLENDİ
    'Lcom/amplitude/': 2.5,
    'Lcom/segment/analytics/': 2.5,     # EKLENDİ
    'Lcom/stripe/android/': 2.0,        # EKLENDİ
    'Lcom/paypal/android/': 2.0,        # EKLENDİ
    'Lcom/braintreepayments/': 2.0,     # EKLENDİ
    'Lcom/twitter/sdk/': 2.0,           # EKLENDİ
    'Lcom/linkedin/android/': 2.0,      # EKLENDİ
    'Landroidx/': 1.5,
    'Lcom/google/android/material/': 2.0,
    'Lbutterknife/': 2.0,
    'Lcom/bumptech/glide/': 2.0,
    'Lcom/airbnb/lottie/': 2.0,
    'Lkotlin/': 1.0,
    'Lokhttp3/': 1.0,
    'Lcom/google/gson/': 1.0,
}

CRITICAL_APIS_HIGH_CONFIDENCE = (
    'Landroid/app/admin/DevicePolicyManager;->wipeData',
    'dispatchGesture',
    'injectSmsPdu',
    'su -c',
    'pm install',
    'Landroid/os/Process;->killProcess',
    'abortBroadcast',
    'setMobileDataEnabled',
    'setWifiEnabled'
)

W = {
    "accessibility": 5.0,
    "overlay": 5,
    "notifications": 4.50,
    "dangerous_permissions": 10,
    "sms": 7.5,
    "admin_operations": 7.0,
    "dynamic": 5.5,
    "vpn": 7.5,
    "telephony": 6.5,
    "keylogging": 6,
    "root_detection": 5,
    "banking_targets": 6.5,
    "camera_capture": 3.5,
    "microphone_capture": 3.5,
    "screenshot": 4.5,
    "clipboard": 4.0,
    "webview": 4.5,
    "shell_exec": 6.5,
    "privileged_ops": 5.5,
    "hooking_frameworks": 5.5,
    "package_info": 6.0,
    "emulator_detection": 6,
    "contacts": 4,
    "device_info": 4.0,
    "account": 3.8,
    "classloader_manipulation": 6.5,
    "intent_hijacking": 6.5,
    "crypto": 5.0,
    "network": 3.5,
    "location": 4,
    "anti_debug": 6,
    "native_code": 5.0,
    "content_provider": 0.75,
    "background_ops": 3.0,
    "reflection": 3.5,
    "obfuscation": 5.0,
    "bluetooth": 1.0,
    "nfc": 1,
    "sensor": 1,
    "calendar": 3.2,
    "file_operations": 1.5,
    "sqlite": 1.5,
    "shared_prefs": 0.5,
    "modern_libs": 0,
    "exfiltration": 8.5,
    "persistence": 5.5,
    "ui_injection": 7.0,
    "data_theft": 8.5,
    "anti_vm": 4.0,         # emulator_detection ile benzer
    "c2_communication": 8.5, # network ile ilişkili ama daha spesifik
    "adware": 1.5,          # Genellikle daha az riskli
    "ransomware": 8.0,       # Yüksek risk
    "spyware": 8.0,         # Yüksek risk
    "permission_abuse": 5.5,
    "analytics": 3.0,
    "payment_sdk": 0.5,     # Yeni: Ödeme SDK'ları genellikle güvenilirdir
    "permissions": 2.0,
    "benign_ui": -0.01,
}


BONUS_CONFIG = {
    "packing_severity": 0.9,
    "empty_graph_severity": 0.85,
    "min_graph_nodes": 5,
    "min_graph_edges": 5,
    "density_threshold_low": 0.05,
    "density_threshold_high": 0.5,
    "combo_scale": 10.0,
    "severity_weights": {
        "admin_operations": 0.8,
        "accessibility": 0.7,
        "reflection": 0.6,
        "native_code": 0.6,
        "crypto": 0.7,
        "dynamic": 0.7,
        "telephony": 0.5,
        "sms": 0.6,
        "contacts": 0.6,
        "device_info": 0.5,
        "network": 0.6,
        "overlay": 0.7,
        "banking_targets": 0.9,
        "keylogging": 0.9,
        "screenshot": 0.6,
        "clipboard": 0.6,
        "root_detection": 0.4,
        "anti_debug": 0.5,
        "emulator_detection": 0.5,
        "shell_exec": 0.75,
        "spyware": 0.9,
        "ransomware": 0.95,
    },
    "max_bonus_raw": 200.0,
    "final_scale": 100.0,
    "benign_ratio_shield": 0.65,
    "benign_shield_factor": 0.80,
    "bonus_a": 0.01,
}