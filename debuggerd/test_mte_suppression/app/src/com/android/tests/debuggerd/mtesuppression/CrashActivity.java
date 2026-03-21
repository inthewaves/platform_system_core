package com.android.tests.debuggerd.mtesuppression;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

/**
 * Activity that triggers MTE crashes for testing cmdline-based suppression matching.
 *
 * Launch with:
 *   am start -n com.android.tests.debuggerd.mtesuppression/.CrashActivity --es mode <mode>
 *
 * Supported modes: suppressed, unsuppressed, direct, cross-dso, same-dso, nognuhash, leaf, gap
 */
public class CrashActivity extends Activity {
    private static final String TAG = "MteSuppressionTestApp";

    static {
        System.loadLibrary("mte_suppression_test_app_jni");
    }

    static native void nativeSuppressedCrash();
    static native void nativeUnsuppressedCrash();
    static native void nativeDirectCrash();
    static native void nativeCrossDsoCrash();
    static native void nativeSameDsoCrash();
    static native void nativeNoGnuHashCrash();
    static native void nativeLeafCrash();
    static native void nativeGapCrash();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String mode = getIntent().getStringExtra("mode");
        if (mode == null) {
            Log.e(TAG, "No mode specified");
            finish();
            return;
        }

        Log.i(TAG, "Triggering crash mode: " + mode);

        switch (mode) {
            case "suppressed":
                nativeSuppressedCrash();
                break;
            case "unsuppressed":
                nativeUnsuppressedCrash();
                break;
            case "direct":
                nativeDirectCrash();
                break;
            case "cross-dso":
                nativeCrossDsoCrash();
                break;
            case "same-dso":
                nativeSameDsoCrash();
                break;
            case "nognuhash":
                nativeNoGnuHashCrash();
                break;
            case "leaf":
                nativeLeafCrash();
                break;
            case "gap":
                nativeGapCrash();
                break;
            default:
                Log.e(TAG, "Unknown mode: " + mode);
                break;
        }

        Log.i(TAG, "Survived crash mode: " + mode);
        finish();
    }
}
