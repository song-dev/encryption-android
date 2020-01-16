#include <jni.h>
#include <string.h>
#include "sm4/sms4.h"
#include "log.h"

#define AES_BLOCK_SIZE 16

extern "C" JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    return env->NewStringUTF("sss");
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1enc(JNIEnv *env, jobject instance,
                                                   jbyteArray data_) {
    jbyte *data = env->GetByteArrayElements(data_, NULL);

    // sm4 对称加密
    sms4_key_t key;
    const unsigned char uKey[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                  0x30, 0x30, 0x30, 0x30, 0x30};
    unsigned char iv[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                          0x30, 0x30, 0x30, 0x30, 0x30};
    sms4_set_encrypt_key(&key, uKey);

    const unsigned char in[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
    int len_origin = sizeof(in) / sizeof(char);

    // pkcs7padding
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

    LOGD("======");

    const unsigned char twoKey[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                  0x30, 0x30, 0x30, 0x30, 0x30};
    unsigned char twoIv[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                          0x30, 0x30, 0x30, 0x30, 0x30};
    unsigned char decData[len_ext];
    sms4_key_t key_two;
    sms4_set_decrypt_key(&key_two, twoKey);
    sms4_cbc_encrypt(out, decData, len_ext, &key_two, twoIv, 0);

    for (int i = 0; i < len_ext; ++i) {
        LOGD("dec: %02x", decData[i]);
    }

    env->ReleaseByteArrayElements(data_, data, 0);
    return env->NewStringUTF("sss");
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1dec(JNIEnv *env, jobject instance, jstring data_) {
    const char *data = env->GetStringUTFChars(data_, JNI_FALSE);
    env->ReleaseStringUTFChars(data_, data);
    return env->NewStringUTF(data);
}