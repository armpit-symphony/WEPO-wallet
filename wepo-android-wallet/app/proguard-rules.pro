# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.kts.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Keep all crypto-related classes
-keep class org.bitcoinj.** { *; }
-keep class org.bouncycastle.** { *; }
-dontwarn org.bitcoinj.**
-dontwarn org.bouncycastle.**

# Keep Retrofit interfaces
-keep,allowobfuscation,allowshrinking interface retrofit2.Call
-keep,allowobfuscation,allowshrinking class retrofit2.Response
-keep,allowobfuscation,allowshrinking class kotlin.coroutines.Continuation

# Keep data classes for serialization
-keep class com.wepo.wallet.data.model.** { *; }

# Keep Hilt generated classes
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class **_HiltModules* { *; }
-keep class **_Factory* { *; }
-keep class **_MembersInjector* { *; }

# Gson rules
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn sun.misc.**
-keep class com.google.gson.examples.android.model.** { <fields>; }
-keep class * extends com.google.gson.TypeAdapter
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Keep security-related classes
-keep class androidx.biometric.** { *; }
-keep class androidx.security.crypto.** { *; }

# Keep Compose runtime classes
-keep class androidx.compose.runtime.** { *; }
-dontwarn androidx.compose.runtime.**

# Keep Android Keystore classes
-keep class android.security.keystore.** { *; }
-keep class java.security.** { *; }

# Keep wallet-specific classes from obfuscation
-keep class com.wepo.wallet.data.local.SecurityManager { *; }
-keep class com.wepo.wallet.data.repository.WalletRepository { *; }

# OkHttp platform used only on JVM and when Conscrypt and other security providers are available.
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**