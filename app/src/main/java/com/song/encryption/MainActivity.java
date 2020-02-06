package com.song.encryption;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("sensebot-lib");
    }

    private String data = null;
    private StringBuffer sb = new StringBuffer();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        setDebug(true);

        // Example of a call to a native method
        final TextView tv = findViewById(R.id.sample_text);


        findViewById(R.id.btn_encrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                // 加密
                sb.append(")OO@L:MCM@?-!@#$%^&*()_+~`{}|,.:; ");
                sb.append("1234567890abcdefghijklmnopqrstuvwxyz");
                data = geetest_enc(sb.toString().getBytes());
                tv.setText(data);
                Log.e(TAG, "encrypted: " + data);

            }
        });

        findViewById(R.id.btn_decrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                // base64 decode 然后截断最后 112 然后 base64encode
                byte[] decode = org.bouncycastle.util.encoders.Base64.decode(data);
                int len = decode.length - 112;
                Log.e(TAG, "decrypted: len: " + len);
                byte dest[] = new byte[len];
                System.arraycopy(decode, 0, dest, 0, len);
                String encode = new String(org.bouncycastle.util.encoders.Base64.encode(dest));

                Log.e(TAG, "decrypted: " + geetest_dec(encode));

            }
        });


    }

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

    public native void setDebug(boolean debug);

}
