package com.song.encryption;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);

        String data = geetest_enc("tesasxbajslbxasjcbsjlct".getBytes());
        tv.setText(data);

        Log.e(TAG, "onCreate: " + data);
        Log.e(TAG, "onCreate: " + geetest_dec(data));
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    /**
     * @param data 待加密字节数据
     * @return 已加密后密文(包括加密sm4key)，已base64编码
     */
    public native String geetest_enc(byte[] data);

    /**
     * @param data 待解密base64数据(包括 sm2加密sm4key)
     * @return 解密后原文
     */
    public native String geetest_dec(String data);
}
