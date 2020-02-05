# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
        native-lib

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        native-lib.cpp
        utils.cpp
        base64.c
        sm4/cbc128.c
        sm4/sms4_cbc.c
        sm4/sms4_enc.c
        sm4/sms4_common.c
        sm4/sms4_setkey.c
#        sm2/sm2_crypt.c
#        sm2/sm2_err.c
#        sm2/sm2_pmeth.c
#        sm2/tasn_dec.c
#        sm2/tasn_new.c
#        sm2/ec_key.c
#        sm2/tasn_enc.c
#        sm2/tasn_fre.c
        sm3/sm3_hmac.c
        sm3/sm3.c
        sms2/GM_sm2.cpp
        sms2/bn_mp_addmod.c
        sms2/bn_mp_copy.c
        sms2/bn_mp_init_copy.c
        sms2/bn_mp_init_multi.c
        sms2/bn_mp_init_set.c
        sms2/bn_error.c
        sms2/bn_mp_add_d.c
        sms2/bn_mp_cmp_d.c
        sms2/bn_mp_read_radix.c
        sms2/bn_mp_add.c
        sms2/bn_mp_clear.c
        sms2/bn_mp_mod.c
        sms2/bn_mp_init.c
        sms2/bn_mp_zero.c
        sms2/bn_mp_invmod.c
        sms2/bn_mp_mul_d.c
        sms2/bn_mp_sub.c
        sms2/bn_mp_submod.c
        sms2/bn_mp_cmp.c
        sms2/bn_mp_sqr.c
        sms2/bn_mp_clamp.c
        sms2/bn_mp_cmp_mag.c
        sms2/bn_mp_div.c
        sms2/bn_mp_grow.c
        sms2/bn_mp_karatsuba_sqr.c
        sms2/bn_mp_set.c
        sms2/bn_mp_sub_d.c
        sms2/bn_mp_toom_sqr.c
        sms2/bn_s_mp_add.c
        sms2/bn_s_mp_sqr.c
        sms2/bn_s_mp_sub.c
        sms2/bn_mp_div_2.c
        sms2/bn_mp_div_3.c
        sms2/bn_mp_mul_2d.c
        sms2/bn_mp_init_size.c
        sms2/bn_mp_exch.c
        sms2/bn_mp_clear_multi.c
        sms2/bn_mp_toradix.c
        sms2/bn_mp_mul.c
        sms2/bn_mp_mulmod.c
        sms2/bn_mp_count_bits.c
        sms2/bn_mp_lshd.c
        sms2/bn_mp_mul_2.c
        sms2/bn_mp_div_d.c
        sms2/bn_mp_mod_2d.c
        sms2/bn_fast_mp_invmod.c
        sms2/bn_mp_prime_random_ex.c
        sms2/bn_mp_invmod_slow.c
        sms2/bn_mp_rshd.c
        sms2/bn_mp_div_2d.c
        sms2/bn_mp_read_signed_bin.c
        sms2/bn_fast_s_mp_mul_digs.c
        sms2/bn_mp_prime_is_prime.c
        sms2/bn_mp_toom_mul.c
        sms2/bn_reverse.c
        sms2/bn_mp_sqrmod.c
        sms2/bn_s_mp_mul_digs.c
        sms2/bn_mp_karatsuba_mul.c
        sms2/bn_mp_read_signed_bin.c
        sms2/bn_prime_tab.c
        sms2/bn_mp_prime_miller_rabin.c
        sms2/bn_mp_exptmod.c
        sms2/bn_mp_cnt_lsb.c
        sms2/bn_s_mp_exptmod.c
        sms2/bn_mp_exptmod_fast.c
        sms2/bn_mp_reduce_is_2k.c
        sms2/bn_mp_reduce_2k_setup.c
        sms2/bn_mp_reduce_2k.c
        sms2/bn_mp_reduce.c
        sms2/bn_mp_dr_setup.c
        sms2/bn_mp_montgomery_reduce.c
        sms2/bn_fast_s_mp_sqr.c
        sms2/bn_mp_read_unsigned_bin.c
        sms2/bn_mp_2expt.c
        sms2/bn_s_mp_mul_high_digs.c
        sms2/bn_fast_mp_montgomery_reduce.c
        sms2/bn_fast_s_mp_mul_high_digs.c
        sms2/bn_mp_montgomery_calc_normalization.c
        sms2/bn_mp_dr_reduce.c
        sms2/bn_mp_montgomery_setup.c
        sms2/bn_mp_abs.c
        sms2/bn_mp_prime_is_divisible.c
        sms2/bn_mp_reduce_2k_l.c
        sms2/bn_mp_mod_d.c
        sms2/bn_mp_reduce_is_2k_l.c
        sms2/bn_mp_dr_is_modulus.c
        sms2/bn_mp_reduce_setup.c
        sms2/bn_mp_reduce_2k_setup_l.c
        sms2/bncore.c
        sms2/bn_mp_toradix.c
        sms2/bn_mp_radix_smap.c
        )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
        native-lib

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})