//
// Created by 陈颂颂 on 2020/2/5.
//

#ifndef ENCRYPTION_ANDROID_ENCRYPT_H
#define ENCRYPTION_ANDROID_ENCRYPT_H

#include <jni.h>

typedef struct DP_BYTES {
    int length;
    char *data;
} DP_BYTES;


int sm2_encrypto(DP_BYTES data, DP_BYTES publicKey, unsigned char *enc_out);

int test_sm2_decrypto(struct DP_BYTES cipherText, struct DP_BYTES privateKey, char out[]);

int sm2_encrypt(unsigned char *sm4_key, char *out);

jstring encrypt(JNIEnv *env, jbyteArray data_, unsigned char *uKey);

jstring decrypt(JNIEnv *env, jstring data_, unsigned char *sm4key);

/**
 * sm4 加密
 * @param env
 * @param data_ 待加密数据
 * @param uKey sm4 key
 * @return 加密后 hexstring 格式数据
 */
jstring encrypt_sm4(JNIEnv *env, jbyteArray data_, unsigned char *uKey);


/**
 * sm4 解密
 * @param env
 * @param data_ 待解密数据 hexstring 格式
 * @return 解密后字符串
 */
jstring decrypt_sm4(JNIEnv *env, jstring data_, unsigned char *sm4key);

/**
 * sm2 公钥加密
 * @param env
 * @param data_ 待加密数据
 * @param uKey sm4 key
 * @return 加密后 base64 数据
 */
jstring encrypt_sm2(JNIEnv *env, unsigned char *uKey);


/**
 * sm2 私钥解密
 * @param env
 * @param data_ 待解密数据
 * @return 解密后字符串
 */
jstring decrypt_sm2(JNIEnv *env, jstring data_);

#endif //ENCRYPTION_ANDROID_ENCRYPT_H
