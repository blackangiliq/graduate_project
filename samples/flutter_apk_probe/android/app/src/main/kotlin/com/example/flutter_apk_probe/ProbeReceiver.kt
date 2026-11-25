package com.example.flutter_apk_probe

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/** Declared as exported without a permission, so that any app can send it a broadcast. */
class ProbeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        Log.i("ProbeReceiver", "received ${intent.action}")
    }
}
