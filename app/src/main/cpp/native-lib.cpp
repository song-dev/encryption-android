#include <jni.h>
#include <string.h>
#include "encrypt.h"
#include "utils.h"
#include "log.h"

extern int debug = 0;
extern unsigned char endKey[17] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                                   0x61, 0x62, 0x63, 0x64, 0x65, 0x66, '\0'};

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1enc(JNIEnv *env, jobject instance,
                                                   jbyteArray data_) {

    unsigned char key[17];
    if (debug) {
        unsigned char normal_key[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                                      0x61, 0x62, 0x63, 0x64, 0x65, 0x66};
        memcpy(key, normal_key, 16);
    } else {
        randomKey(key);
    }
    // 保存当前 key
    key[16] = '\0';
    memcpy(endKey, key, 17);

    // 随机生成 key 或者 固定的 key
    LOGD("encrypt key: %s", key);
    jstring result = encrypt(env, data_, key);
    return result;

}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1dec(JNIEnv *env, jobject instance, jstring data_) {

    LOGD("decrypt key: %s", endKey);
    jstring result = decrypt(env, data_, endKey);
    return result;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_song_encryption_MainActivity_setDebug(JNIEnv *env, jobject instance, jboolean mDebug) {

    if (mDebug) {
        debug = 1;
    } else {
        debug = 0;
    }
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1sm2_1dec(JNIEnv *env, jobject instance,
                                                        jstring data_) {
    LOGD("decrypt key: %s", endKey);
    return decrypt_sm2(env, data_);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1sm4_1enc(JNIEnv *env, jobject instance,
                                                        jbyteArray data_) {
    unsigned char key[17];
    if (debug) {
        unsigned char normal_key[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                                      0x61, 0x62, 0x63, 0x64, 0x65, 0x66};
        memcpy(key, normal_key, 16);
    } else {
        randomKey(key);
    }
    // 保存当前 key
    key[16] = '\0';
    memcpy(endKey, key, 17);

    // 随机生成 key 或者 固定的 key
    LOGD("encrypt key: %s", key);
    jstring result = encrypt_sm4(env, data_, key);
    return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1sm4_1dec(JNIEnv *env, jobject instance,
                                                        jstring data_) {
    return decrypt_sm4(env, data_, endKey);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_song_encryption_MainActivity_geetest_1sm2_1enc(JNIEnv *env, jobject instance) {
    LOGD("encrypt key: %s", endKey);
    return encrypt_sm2(env, endKey);
}