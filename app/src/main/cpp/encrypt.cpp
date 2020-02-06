//
// Created by 陈颂颂 on 2020/2/5.
//

#include "encrypt.h"

#include <jni.h>
#include <string.h>
#include "sm4/sms4.h"
#include "log.h"
#include "sms2/GM_sm2.h"
#include "utils.h"
#include "base64.h"

#define AES_BLOCK_SIZE 16
#define LENGTH_SM2_ENC 96
#define ENCRYPT_OK 0
#define ENCRYPT_ERR 1

/**
 *
 * @param data 待加密数据
 * @param publicKey sm2 公钥
 * @param enc_out 加密后数据，已去掉开头 0x04
 * @return 加密状态
 */
int sm2_encrypto(DP_BYTES data, DP_BYTES publicKey, unsigned char *enc_out) {

    unsigned long len_out = data.length + LENGTH_SM2_ENC + 1;
    unsigned char result[len_out];

    int ret = GM_SM2Encrypt(result, &len_out, (unsigned char *) (data.data), data.length,
                            (unsigned char *) publicKey.data,
                            publicKey.length);

    if (len_out < 2 || ret != MP_OKAY) {
        // 加密出错了
        return ENCRYPT_ERR;
    }

    // 打印加密后长度
    LOGD("sm2 encrypted len_out: %lu", len_out);
    for (int i = 0; i < len_out; ++i) {
        LOGD("sm2_encrypto: %02x", result[i]);
    }

    // 去掉第一位的 0x04
    memcpy(enc_out, result + 1, data.length + LENGTH_SM2_ENC);
    return ENCRYPT_OK;
}

unsigned char *test_sm2_decrypto(struct DP_BYTES cipherText, struct DP_BYTES privateKey) {

    //密文长度至少也需要64+32位
    if (cipherText.length < LENGTH_SM2_ENC || privateKey.length == 0) {
        return NULL;
    }

    unsigned long out_len = cipherText.length - 64 - 32;
    unsigned long pass_len = cipherText.length + 1;
    unsigned char result[out_len];
    unsigned char pass[pass_len];

    memset(&result, 0, out_len);
    memset(&pass, 0, pass_len);

    LOGD("decrypted len: %lu", out_len);
    LOGD("pass len: %lu", pass_len);

    pass[0] = '\x04'; //需要补一位\x04
    memcpy(pass + 1, cipherText.data, cipherText.length);

    int ret = GM_SM2Decrypt(result, &out_len, pass, pass_len,
                            (unsigned char *) privateKey.data, privateKey.length);

    LOGD("ret: %d", ret);
    if (out_len == 0 || ret != MP_OKAY) {
        //解密出错了
        return NULL;
    }

    return result;
}

/**
 * @param sm4_key
 * @param out
 * @return 加密状态
 */
int sm2_encrypt(unsigned char *sm4_key, char *out) {

    char publicKey[] = "bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac";
    char priviteKey[] = "42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6";
    // 待加密 sm4 key
//    char sm4_key[] = "0123456789abcdef";

    // 将hex转byte公钥和私钥
    int len_pub = strlen(publicKey);
    int len_pri = strlen(priviteKey);

    char publicKeyLast[len_pub / 2];
    hexstrToByte(publicKey, publicKeyLast, len_pub);
    len_pub = len_pub / 2;

    // 输出转化后的bytes
    LOGD("len_pub: %d", len_pub);
//    for (int i = 0; i < len_pub; ++i) {
//        LOGD("pub: %02x", publicKeyLast[i]);
//    }

    char privateKeyLast[len_pri / 2];
    hexstrToByte(priviteKey, privateKeyLast, len_pri);
    len_pri = len_pri / 2;

    // 输出转化后的bytes
    LOGD("len_pri: %d", len_pri);
//    for (int i = 0; i < len_pri; ++i) {
//        LOGD("pri: %02x", privateKeyLast[i]);
//    }

    struct DP_BYTES publicKeyC = {};
    publicKeyC.data = publicKeyLast;
    publicKeyC.length = len_pub;

    struct DP_BYTES privateKeyC = {};
    privateKeyC.data = privateKeyLast;
    privateKeyC.length = len_pri;

    struct DP_BYTES sm2PlainStrC = {};
    sm2PlainStrC.data = (char *) sm4_key;
    sm2PlainStrC.length = strlen((char *) sm4_key);

    int len_enc = sm2PlainStrC.length + LENGTH_SM2_ENC;

    // sm2 加密
    unsigned char data_enc[len_enc];
    int result_code = sm2_encrypto(sm2PlainStrC, publicKeyC, data_enc);

    for (int i = 0; i < len_enc; ++i) {
        LOGD("SM2 encrypted: %02x", data_enc[i]);
    }
    memcpy(out, data_enc, len_enc);

    return result_code;

//    struct DP_BYTES sm2CipherTextC = {};
//    sm2CipherTextC.data = (char *) data_enc;
//    sm2CipherTextC.length = len_enc;
//    unsigned char *result = test_sm2_decrypto(sm2CipherTextC, privateKeyC);

}


/**
 * 加密
 * @param env
 * @param data_ 待加密数据
 * @param uKey sm4 key
 * @return 加密后 base64 数据
 */
jstring encrypt(JNIEnv *env, jbyteArray data_, unsigned char *uKey) {

    // 待加密数据长度
    jsize len_origin = env->GetArrayLength(data_);
    // 转化为指针
    jbyte *in = env->GetByteArrayElements(data_, JNI_FALSE);

    // sm4 加密 data sm2 加密key 最终合并 base64处理
    sms4_key_t key;
    unsigned char iv[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                          0x30, 0x30, 0x30, 0x30, 0x30};
    sms4_set_encrypt_key(&key, uKey);

    int len_padding = AES_BLOCK_SIZE - len_origin % AES_BLOCK_SIZE;
    int len_ext = len_origin + len_padding;
    LOGE("ext data len: %d, padding len: %d, origin data len: %d", len_ext, len_padding,
         len_origin);

    uint8_t padding[len_padding];
    memset(padding, len_padding, len_padding);

    // 链接数据
    uint8_t data_ext[len_ext];
    memcpy((char *) data_ext, in, len_origin);
    memcpy((char *) (data_ext + len_origin), (char *) padding, len_padding);
    unsigned char out[len_ext];

//    for (int i = 0; i < len_ext; ++i) {
//        LOGD("origin: %02x", data_ext[i]);
//    }

    sms4_cbc_encrypt(data_ext, out, len_ext, &key, iv, 1);

//    for (int i = 0; i < len_ext; ++i) {
//        LOGD("out: %02x", out[i]);
//    }

    int len_sm4 = strlen((char *) uKey);
    LOGE("len_sm4: %d",len_sm4);

    int len_sm2 = len_sm4 + LENGTH_SM2_ENC;
    char sm2_out[len_sm2];
    sm2_encrypt(uKey, sm2_out);

    // 拼接加密后数据和 sm2 加密后 key
    unsigned char end[len_ext + len_sm2];
    memcpy(end, out, len_ext);
    memcpy(end + len_ext, sm2_out, len_sm2);

    LOGE("encrypted length: %d", len_ext + len_sm2);
    LOGE("encrypted len_ext: %d", len_ext);
    LOGE("encrypted len_sm2: %d", len_sm2);

    // base64 编码处理
    char *b64_end = b64_encode(end, len_ext + len_sm2);
    LOGE("encrypted base64 length: %d", strlen(b64_end));

    env->ReleaseByteArrayElements(data_, in, 0);
    return env->NewStringUTF(b64_end);

}


/**
 * 解密
 * @param env
 * @param data_ 待解密数据
 * @return 解密后字符串
 */
jstring decrypt(JNIEnv *env, jstring data_, unsigned char *sm4key) {

    const char *data = env->GetStringUTFChars(data_, JNI_FALSE);
    jsize len_origin = env->GetStringUTFLength(data_);
    LOGD("len: %d base64 data: %s", len_origin, data);

    // 传入 base64 字符串，解析为原数据
    size_t len_dec;
    unsigned char *origin = b64_decode_ex(data, len_origin, &len_dec);
    size_t len_ext = len_dec;
    unsigned char in[len_ext];
    memcpy(in, origin, len_ext);

    LOGD("len_ext: %zu len_dec: %zu", len_ext, len_dec);
//    for (int i = 0; i < len_ext; ++i) {
//        LOGD("dec in: %02x", in[i]);
//    }

    unsigned char iv[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                             0x30, 0x30, 0x30, 0x30, 0x30};
    unsigned char decData[len_ext];
    sms4_key_t key;
    sms4_set_decrypt_key(&key, sm4key);
    sms4_cbc_encrypt(in, decData, len_ext, &key, iv, 0);

//    for (int i = 0; i < len_ext; ++i) {
//        LOGD("decrypted: %c", decData[i]);
//    }

    // 去除padding
    int padding_dec = decData[len_ext - 1];
    int len_dec_data = len_ext - padding_dec;
    char data_origin[len_dec_data + 1];
    memcpy(data_origin, decData, len_dec_data);
    data_origin[len_dec_data] = '\0';

    LOGD("padding_dec: %d len_dec_data: %d", padding_dec, len_dec_data);

    env->ReleaseStringUTFChars(data_, data);
    return env->NewStringUTF(data_origin);

}
