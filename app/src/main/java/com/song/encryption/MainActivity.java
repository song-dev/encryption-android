package com.song.encryption;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.net.URLEncoder;
import java.util.Random;

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

        final Gt3GMEncryption gt3GMEncryption = new Gt3GMEncryption();
        gt3GMEncryption.setDebug(false);

        // Example of a call to a native method
        final TextView tv = findViewById(R.id.sample_text);


        findViewById(R.id.btn_encrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

//                // 加密
//                sb.append(")OO@L:MCM@?-!@#$%^&*()_+~`{}|,.:; ");
//                sb.append("1234567890abcdefghijklmnopqrstuvwxyz");
//                data = geetest_enc(sb.toString().getBytes());
//                tv.setText(data);
//
//                Log.e(TAG, "encrypted: " + data);
//
//                String sm2_enc = geetest_sm2_enc();
//
//                Log.e(TAG, "sm2 enc: " + sm2_enc);
//
//                String sm4_enc = geetest_sm4_enc(sb.toString().getBytes());
//
//                Log.e(TAG, "sm4 encrypted: " + sm4_enc);
//
//                Log.e(TAG, "sm4 decrypted: " + geetest_sm4_dec(sm4_enc));
//
//                Log.e(TAG, "sm2 decrypted: " + geetest_sm2_dec(sm2_enc));
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        for (int i = 1; i <= 1; i++) {
                            String temp = getRandomString(100);
                            String key = "19e5566778197e07288c9caadcbf47673ffa818e2a76ee62e3bea16b884c46e3eda660fee9b9e6cd03f726aeaf7a1a52bf319e44b19c242d95613ff28c030e03";
//                            String temp = "0123456789abcdef";
                            Log.e(TAG, "当前轮序：" + i);
//                            Log.e(TAG, "temp 值：" + temp);
                            String encTempwithkey = gt3GMEncryption.geetest_enc(temp.getBytes(), key);
//                            String encTemp = gt3GMEncryption.geetest_enc(temp.getBytes());
//                            Log.e(TAG, "加密结果：" + encTemp);
                            Log.e(TAG, "加密结果withkey：" + encTempwithkey);

                            String responseValues = HttpUtils.requestGet("http://10.0.0.196:1081/gm_decrypt?data=" + URLEncoder.encode(encTempwithkey));
                            Log.e(TAG, "解密结果：" + responseValues );
                            Log.e(TAG, "请求是否相等：" + temp.equals(responseValues) + "       " + i);
                            Log.e(TAG, "本地是否相等：" + temp.equals(gt3GMEncryption.geetest_dec(encTempwithkey)) + "       " + i);
                        }
                    }
                }).start();

            }
        });

        findViewById(R.id.btn_decrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                // base64 decode 然后截断最后 112 然后 base64encode
//                byte[] decode = org.bouncycastle.util.encoders.Base64.decode(data);
//                int len = decode.length - 112;
//                Log.e(TAG, "decrypted: len: " + len);
//                byte dest[] = new byte[len];
//                System.arraycopy(decode, 0, dest, 0, len);
//                String encode = new String(org.bouncycastle.util.encoders.Base64.encode(dest));

                int len = data.length() - 112*2;
                String s = data.substring(0,len);
                Log.e(TAG, "decrypted: " + gt3GMEncryption.geetest_dec(s));

            }
        });


    }

    public static String getRandomString(int length) {
        String base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}!@#$%^&*()_+";
        return getRandomString(length, base);
    }

    private static String getRandomString(int length, String base) {
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }



}
