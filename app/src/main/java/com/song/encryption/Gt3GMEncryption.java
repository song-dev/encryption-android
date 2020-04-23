package com.song.encryption;

public class Gt3GMEncryption {
    /**
     * @param data 待加密字节数据
     * @return 已加密后密文(包括加密sm4key)，已base64编码
     */
//    public native String geetest_enc(byte[] data);

    /**
     * @param data 待解密base64数据(包括 sm2加密sm4key)
     * @return 解密后原文
     */
    public native String geetest_dec(String data);

    public native String geetest_enc(byte[] data, String SM2_key);

    public native void setDebug(boolean debug);

    public native String geetest_sm2_enc();

    public native String geetest_sm2_dec(String data);

    public native String geetest_sm4_enc(byte[] data);

    public native String geetest_sm4_dec(String data);

}
