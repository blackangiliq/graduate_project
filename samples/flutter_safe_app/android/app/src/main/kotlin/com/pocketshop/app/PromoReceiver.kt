package com.pocketshop.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Stores a promotion code that the app itself broadcasts; it is applied at checkout. */
class PromoReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val code = intent.getStringExtra("promo_code") ?: return
        context.getSharedPreferences("promo", Context.MODE_PRIVATE)
            .edit()
            .putString("pending_code", code)
            .apply()
    }
}
