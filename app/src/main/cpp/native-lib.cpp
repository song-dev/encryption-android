#include <jni.h>
#include <string.h>
#include "sm4/sms4.h"
#include "log.h"
#include "sms2/GM_sm2.h"
#include "utils.h"
#include "base64.h"

#define AES_BLOCK_SIZE 16

typedef struct DP_BYTES {
    int length;
    char *data;
};

extern "C" JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    return env->NewStringUTF("sss");
}

unsigned char *test_sm2_encrypto(struct DP_BYTES data, struct DP_BYTES publicKey) {
//    NSData *keyData = [NSData dataFromHexString:publicKey];

    unsigned long len_out = data.length + 64 + 32 + 1;
    unsigned char result[len_out];

    int ret = GM_SM2Encrypt(result, &len_out, (unsigned char *) (data.data), data.length,
                            (unsigned char *) publicKey.data,
                            publicKey.length);

    if (len_out < 2 || ret != MP_OKAY) {
        // 加密出错了
        return NULL;
    }

    // 打印加密后长度
    LOGD("len_out: %u", len_out);
    for (int i = 0; i < len_out; ++i) {
        LOGD("test_sm2_encrypto: %.2x", result[i]);
    }

    // 多一位\x04 需要去掉
//    NSData *outData = [NSData dataWithBytes:result + 1 length:outlen - 1];
//    NSString *encrypStr = [outData hexStringFromData:outData];
//    return result;

    // 去掉第一位的 0x04
    unsigned char end[data.length + 64 + 32];
    memcpy(end, result + 1, data.length + 64 + 32);
    return end;
}

unsigned char *test_sm2_decrypto(struct DP_BYTES cipherText, struct DP_BYTES privateKey) {
    //密文长度至少也需要64+32位
    if (cipherText.length < 64 + 32 || privateKey.length == 0) {
        return NULL;
    }

//    NSData *keyData = [NSData dataFromHexString:privateKey];
//    NSData *data = [NSData dataFromHexString:cipherText];

    unsigned long out_len = cipherText.length - 64 - 32;
    unsigned long pass_len = cipherText.length + 1;
    unsigned char result[out_len];
    unsigned char pass[pass_len];

    memset(&result, 0, out_len);
    memset(&pass, 0, pass_len);

    LOGD("decrypted len: %u", out_len);
    LOGD("pass len: %u", pass_len);

    pass[0] = '\x04'; //需要补一位\x04
    memcpy(pass + 1, cipherText.data, cipherText.length);
//    memcpy(pass, cipherText.data, cipherText.length);

    int ret = GM_SM2Decrypt(result, &out_len, pass, pass_len,
                            (unsigned char *) privateKey.data, privateKey.length);

    LOGD("ret: %d", ret);
    if (out_len == 0 || ret != MP_OKAY) {
        //解密出错了
        return NULL;
    }

//    NSData *origData = [NSData dataWithBytes:result length:out_len];

    return result;
}

void sm2_encrypt(char *out) {

    char publicKey[] = "bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac";
    char priviteKey[] = "42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6";
    char sm2_plain_str[] = "0123456789abcdef";

//    NSLog(@"SM2 原文长度: %ld, 密文==========>%@", sm2_plain_str.length, sm2_plain_str.lowercaseString);

//    NSData *sm2PublicKeyData = [NSData dataFromHexString:publicKey];
//    NSData *sm2PrivateKeyData = [NSData dataFromHexString:priviteKey];
//    NSData *sm2PlainData = [sm2_plain_str dataUsingEncoding:NSUTF8StringEncoding];


    // 将hex转byte公钥和私钥
    int len_pub = strlen(publicKey);
    int len_pri = strlen(priviteKey);

    char publicKeyLast[len_pub / 2];
    hexstrToByte(publicKey, publicKeyLast, len_pub);
    len_pub = len_pub / 2;

    // 输出转化后的bytes
    LOGD("len_pub: %d", len_pub);
    for (int i = 0; i < len_pub; ++i) {
        LOGD("pub: %.2x", publicKeyLast[i]);
    }

    char privateKeyLast[len_pri / 2];
    hexstrToByte(priviteKey, privateKeyLast, len_pri);
    len_pri = len_pri / 2;

    // 输出转化后的bytes
    LOGD("len_pri: %d", len_pri);
    for (int i = 0; i < len_pri; ++i) {
        LOGD("pri: %.2x", privateKeyLast[i]);
    }

    struct DP_BYTES publicKeyC = {};
    publicKeyC.data = publicKeyLast;
    publicKeyC.length = len_pub;

    struct DP_BYTES privateKeyC = {};
    privateKeyC.data = privateKeyLast;
    privateKeyC.length = len_pri;

    struct DP_BYTES sm2PlainStrC = {};
    sm2PlainStrC.data = sm2_plain_str;
    sm2PlainStrC.length = strlen(sm2_plain_str);

    unsigned char *sm2CipherHexText = test_sm2_encrypto(sm2PlainStrC, publicKeyC);

    for (int i = 0; i < sm2PlainStrC.length + 64 + 32; ++i) {
        LOGD("SM2 encrypted: %.2x", sm2CipherHexText[i]);
    }

    memcpy(out, sm2CipherHexText, sm2PlainStrC.length + 64 + 32);

//    NSData *sm2CipherTextData = [NSData dataFromHexString:sm2CipherHexText];

    struct DP_BYTES sm2CipherTextC = {};
    sm2CipherTextC.data = (char *) sm2CipherHexText;
    sm2CipherTextC.length = sm2PlainStrC.length + 64 + 32;

    unsigned char *result = test_sm2_decrypto(sm2CipherTextC, privateKeyC);

//    for (int i = 0; i < strlen((char*)result); ++i) {
//        LOGD("SM2 decrypted: %.2x", result[i]);
//    }


}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1enc(JNIEnv *env, jobject instance,
                                                   jbyteArray data_) {

    // 待加密数据长度
    jsize len_origin = env->GetArrayLength(data_);
    // 转化为指针
    jbyte *in = env->GetByteArrayElements(data_, JNI_FALSE);
//    const unsigned char in[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
//                                0x30, 0x30, 0x30, 0x30, 0x30};
//    int len_origin = sizeof(in) / sizeof(char);

    // pkcs7padding

    // sm4 加密 data sm2 加密key 最终合并 base64处理

    // 传入数据 sm4
    sms4_key_t key;
    // 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66
    const unsigned char uKey[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                  0x30, 0x30, 0x30, 0x30, 0x30};
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

    for (int i = 0; i < len_ext; ++i) {
        LOGD("origin: %02x", data_ext[i]);
    }

    LOGD("======");

    sms4_cbc_encrypt(data_ext, out, len_ext, &key, iv, 1);

    for (int i = 0; i < len_ext; ++i) {
        LOGD("out: %02x", out[i]);
    }

    char sm2_out[112];
    sm2_encrypt(sm2_out);

    // 拼接加密后数据和 sm2 加密后 key
    unsigned char end[len_ext + 112];
    memcpy(end, out, len_ext);
    memcpy(end + len_ext, sm2_out, 112);

    char *b64_end = b64_encode(end, len_ext + 112);

    env->ReleaseByteArrayElements(data_, in, 0);
    return env->NewStringUTF(b64_end);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1dec(JNIEnv *env, jobject instance, jstring data_) {
    const char *data = env->GetStringUTFChars(data_, JNI_FALSE);
    jsize len_origin = env->GetStringUTFLength(data_);
    LOGD("len: %d base64 data: %s", len_origin, data);

    // 传入 base64 字符串，解析为原数据
    size_t len_dec;
    unsigned char *origin = b64_decode_ex(data, len_origin, &len_dec);
    size_t len_ext = len_dec - 112;
    unsigned char in[len_ext];
    memcpy(in, origin, len_ext);

    LOGD("dec len: %d dec origin len: %d", len_ext, len_dec);
    for (int i = 0; i < len_ext; ++i) {
        LOGD("dec in: %.2x", in[i]);
    }

    // sm4 解密，数据长度传入获取

    const unsigned char twoKey[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                    0x30,
                                    0x30, 0x30, 0x30, 0x30, 0x30};
    unsigned char twoIv[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                             0x30, 0x30, 0x30, 0x30, 0x30};
    unsigned char decData[len_ext];
    sms4_key_t key_two;
    sms4_set_decrypt_key(&key_two, twoKey);
    sms4_cbc_encrypt(in, decData, len_ext, &key_two, twoIv, 0);

    for (int i = 0; i < len_ext; ++i) {
        LOGD("dec: %c", decData[i]);
    }
    // 去除padding

    int padding_dec = decData[len_ext - 1];
    int len_dec_data = len_ext - padding_dec;
    char data_origin[len_dec_data+1];
    memcpy(data_origin, decData, len_dec_data);
    data_origin[len_dec_data] = '\0';

    LOGD("padding_dec: %d len_dec_data: %d", padding_dec, len_dec_data);

    env->ReleaseStringUTFChars(data_, data);

    return env->NewStringUTF(data_origin);
}