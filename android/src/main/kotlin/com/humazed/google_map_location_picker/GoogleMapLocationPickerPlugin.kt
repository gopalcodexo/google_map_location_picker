package com.humazed.google_map_location_picker

import androidx.annotation.NonNull

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import android.content.pm.PackageManager
import java.math.BigInteger
import java.security.MessageDigest
import android.content.pm.PackageInfo

class GoogleMapLocationPickerPlugin : FlutterPlugin, MethodCallHandler, ActivityAware  {
    private lateinit var channel : MethodChannel
    private var activityBinding: ActivityPluginBinding? = null

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "google_map_location_picker")
        channel.setMethodCallHandler(this)
    }

/*    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        if(activityBinding == null) {
            result.notImplemented()
            return
        }
        if (call.method == "getSigningCertSha1") {
            try {
                val info: PackageInfo = activityBinding!!.activity.packageManager.getPackageInfo(call.arguments<String?>(), PackageManager.GET_SIGNATURES)
                for (signature in info.signatures) {
                    val md: MessageDigest = MessageDigest.getInstance("SHA1")
                    md.update(signature.toByteArray())

                    val bytes: ByteArray = md.digest()
                    val bigInteger = BigInteger(1, bytes)
                    val hex: String = String.format("%0" + (bytes.size shl 1) + "x", bigInteger)

                    result.success(hex)
                }
            } catch (e: Exception) {
                result.error("ERROR", e.toString(), null)
            }
        } else {
            result.notImplemented()
        }
    }*/

    override fun onMethodCall(call: MethodCall, result: Result) {
        // Check if activityBinding is null, and if so, return notImplemented().
        if (activityBinding == null) {
            result.notImplemented()
            return
        }

        // Check if the method being called is "getSigningCertSha1".
        if (call.method == "getSigningCertSha1") {
            try {
                // Get the package name from the arguments. Since it's a nullable String, we need to handle null safely.
                val packageName: String? = call.argument<String>("packageName")

                if (packageName == null) {
                    // If the package name is null, return an error.
                    result.error("ERROR", "Package name is null", null)
                    return
                }

                // Get the PackageInfo for the specified package.
                val packageManager = activityBinding!!.activity.packageManager
                val packageInfo: PackageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)

                // Loop through the signatures (usually, there's only one signature).
                for (signature in packageInfo.signatures) {
                    // Calculate the SHA1 fingerprint of the signature.
                    val md: MessageDigest = MessageDigest.getInstance("SHA1")
                    md.update(signature.toByteArray())
                    val bytes: ByteArray = md.digest()

                    // Convert the SHA1 fingerprint to hexadecimal format.
                    val bigInteger = BigInteger(1, bytes)
                    val hex: String = String.format("%0" + (bytes.size shl 1) + "x", bigInteger)

                    // Return the SHA1 fingerprint to Flutter.
                    result.success(hex)
                }
            } catch (e: Exception) {
                // If an exception occurs during the process, return an error.
                result.error("ERROR", e.toString(), null)
            }
        } else {
            // If the method called is not "getSigningCertSha1", return notImplemented().
            result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
    }

    override fun onDetachedFromActivity() {
        activityBinding = null
    }

    override fun onDetachedFromActivityForConfigChanges() {
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    }
}
