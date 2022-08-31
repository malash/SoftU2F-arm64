//
//  ssl.c
//  SoftU2F
//
//  Created by Malash on 8/31/22.
//  Copyright © 2022 GitHub. All rights reserved.
//

#include "ssl.h"
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int generate_key( void )
{
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }
    
    
    //we use a memory BIO to store the keys
    bp_public = BIO_new(BIO_s_mem());
//    PEM_write_bio_RSAPublicKey(bp_public, r);
    bp_private = BIO_new(BIO_s_mem());
//    PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    
    int pri_len = BIO_pending(bp_private);
    
    printf("%d", pri_len);
    
//    // 2. save public key
//    bp_public = BIO_new_file("public.pem", "w+");
//    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
//    if(ret != 1){
//        goto free_all;
//    }
//
//    // 3. save private key
//    bp_private = BIO_new_file("private.pem", "w+");
//    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free
    free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}
