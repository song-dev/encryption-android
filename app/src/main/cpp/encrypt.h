//
// Created by 陈颂颂 on 2020/2/5.
//

#ifndef ENCRYPTION_ANDROID_ENCRYPT_H
#define ENCRYPTION_ANDROID_ENCRYPT_H

#include <jni.h>

typedef struct DP_BYTES {
    int length;
    char *data;
}DP_BYTES;


int sm2_encrypto(DP_BYTES data, DP_BYTES publicKey, unsigned char *enc_out);

unsigned char *test_sm2_decrypto(struct DP_BYTES cipherText, struct DP_BYTES privateKey);

int sm2_encrypt(unsigned char *sm4_key, char *out);

jstring encrypt(JNIEnv *env, jbyteArray data_, unsigned char *uKey);

jstring decrypt(JNIEnv *env, jstring data_, unsigned char *sm4key);

#endif //ENCRYPTION_ANDROID_ENCRYPT_H
