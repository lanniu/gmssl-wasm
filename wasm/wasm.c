#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>

#ifndef EM_PORT_API
#	if defined(__EMSCRIPTEN__)
#		include <emscripten.h>
#		if defined(__cplusplus)
#			define EM_PORT_API(rettype) extern "C" rettype EMSCRIPTEN_KEEPALIVE
#		else
#			define EM_PORT_API(rettype) rettype EMSCRIPTEN_KEEPALIVE
#		endif
#	else
#		if defined(__cplusplus)
#			define EM_PORT_API(rettype) extern "C" rettype
#		else
#			define EM_PORT_API(rettype) rettype
#		endif
#	endif
#endif

EM_PORT_API(char*) iasp_sm3(char* plaintext, size_t plain_len) {
	SM3_CTX sm3_ctx;
	uint8_t digest[32];
	size_t i = 0;

	// 此处创建，作为返回值返回，需要在外部释放
	char* hex_digest = (char*)malloc(sizeof(digest) * 2 + 1);
	
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, (uint8_t *)plaintext, plain_len);
	sm3_finish(&sm3_ctx, digest);

	for (i = 0; i < sizeof(digest); i++) {
		sprintf(hex_digest + i * 2, "%02x", (unsigned char)digest[i]);
	}
	return hex_digest;
}

int lcm16(int num) {
    if (num % 16 == 0) {
        return num;
    } else {
        return ((int)ceil((double)num / 16.0)) * 16;
    }
}

EM_PORT_API(char*) iasp_sm4_encrypt(char* key, size_t key_len, char* iv, size_t iv_len, char* plaintext, size_t plain_len) {
	SM4_KEY sm4_key;

	size_t clen_cal = lcm16(plain_len);
	char* cbuf = (char*)malloc(clen_cal);

	size_t i = 0;
	size_t clen = 0;

	sm4_set_encrypt_key(&sm4_key, (uint8_t*)key);

	if(sm4_cbc_padding_encrypt(&sm4_key, (uint8_t*)iv, (uint8_t*)plaintext, plain_len, (uint8_t*)cbuf, &clen) != 1){
		fprintf(stderr, "[wasm][sm4] cbc padding 加密失败 \n");
		free(cbuf); // 释放内存
		return NULL;
	}
	// 此处创建，作为返回值返回，需要在外部释放
	char* hex_cbuf = (char*)malloc(clen * 2 + 1);

	for (i = 0; i < clen; i++) {
		sprintf(hex_cbuf + i * 2, "%02x", (unsigned char)cbuf[i]);
	}
	free(cbuf);
	return hex_cbuf;
}

EM_PORT_API(char*) iasp_sm4_decrypt(char* key, size_t key_len, char* iv, size_t iv_len, char* ciphertext, size_t cipher_len) {
	SM4_KEY sm4_key;

	size_t plen_cal = lcm16(cipher_len);
	// 此处创建，作为返回值返回，需要在外部释放
	char* pbuf = (char*)malloc(plen_cal);
	memset(pbuf, 0, plen_cal);

	size_t i = 0;
	size_t plen = 0;

	sm4_set_decrypt_key(&sm4_key, (uint8_t*)key);

	if(sm4_cbc_padding_decrypt(&sm4_key, (uint8_t*)iv, (uint8_t*)ciphertext, cipher_len, (uint8_t*)pbuf, &plen) != 1){
		fprintf(stderr, "[wasm][sm4] cbc padding 解密失败 \n");
		free(pbuf); // 报错，释放内存
		return NULL;
	}
	return pbuf;
}

int read_sm2_pri_key(char* pri_buff, size_t pri_buff_len, SM2_KEY *pri_key) {
	FILE *pri_stream = fmemopen(pri_buff, pri_buff_len, "r");
    
	if (pri_stream == NULL) {
        fprintf(stderr, "[wasm][sm2] 开启私钥的内存流失败 \n");
        return -1;
    }
	fseek(pri_stream, 0, SEEK_SET);

	if(sm2_private_key_info_from_pem(pri_key, pri_stream) != 1) {
		fprintf(stderr, "[wasm][sm2] 从内存流中读取私钥信息失败 \n");
		fclose(pri_stream); // 关闭内存流
		return -1;
	}
	fclose(pri_stream);
	return 0;
}

int read_sm2_pub_key(char* pub_buff, size_t pub_buff_len, SM2_KEY *pub_key) {
	FILE *pub_stream = fmemopen(pub_buff, pub_buff_len, "r");
    
	if (pub_stream == NULL) {
        fprintf(stderr, "[wasm][sm2] 开启公钥的内存流失败 \n");
        return -1;
    }
	fseek(pub_stream, 0, SEEK_SET);

	if(sm2_public_key_info_from_pem(pub_key, pub_stream) != 1){
		fprintf(stderr, "[wasm][sm2] 从内存流中读取公钥信息失败 \n");
		fclose(pub_stream); // 关闭内存流
		return -1;
	}
	fclose(pub_stream);
	return 0;
}

EM_PORT_API(void) iasp_sm2_gen(char* pri_buff, size_t pri_buff_len, char* pub_buff, size_t pub_buff_len) {
	SM2_KEY sm2_key;

	if (sm2_key_generate(&sm2_key) != 1) {
		fprintf(stderr, "[wasm][sm2] 生成密钥对失败 \n");
		return;
	}
    FILE *pri_stream = fmemopen(pri_buff, pri_buff_len, "w+");
    
	if (pri_stream == NULL) {
        fprintf(stderr, "[wasm][sm2] 开启私钥的内存流失败 \n");
        return;
    }
	FILE *pub_stream = fmemopen(pub_buff, pub_buff_len, "w+");
    
	if (pub_stream == NULL) {
        fprintf(stderr, "[wasm][sm2] 开启公钥的内存流失败 \n");
		fclose(pri_stream); // 关闭内存流
        return;
    }

	if (sm2_private_key_info_to_pem(&sm2_key, pri_stream) != 1) {
		fprintf(stderr, "[wasm][sm2] 将私钥信息写入内存流失败 \n");
	}
	if (sm2_public_key_info_to_pem(&sm2_key, pub_stream) != 1) {
		fprintf(stderr, "[wasm][sm2] 将公钥信息写入内存流失败 \n");
	}
	fclose(pri_stream);
	fclose(pub_stream);
}

EM_PORT_API(char*) iasp_sm2_encrypt(char* pub_buff, size_t pub_buff_len, char* plaintext, size_t plain_len) {
	SM2_KEY pub_key;
	
	if(read_sm2_pub_key(pub_buff, pub_buff_len, &pub_key) < 0){
		return NULL;
	}
	char* ciphertext = (char *)malloc(SM2_MAX_CIPHERTEXT_SIZE);
	size_t cipher_len;

	if(sm2_encrypt(&pub_key, (uint8_t *)plaintext, plain_len, (uint8_t *)ciphertext, &cipher_len) != 1){
		fprintf(stderr, "[wasm][sm2] 加密失败 \n");
		free(ciphertext); // 报错，提前释放内存
		return NULL;
	}
	// 此处创建，作为返回值返回，需要在外部释放
	char* hex_ciphertext = (char*)malloc(cipher_len * 2 + 1);

	for (size_t i = 0; i < cipher_len; i++) {
		sprintf(hex_ciphertext + i * 2, "%02x", (unsigned char)ciphertext[i]);
	}
	free(ciphertext);
	return hex_ciphertext;
}

EM_PORT_API(char*) iasp_sm2_decrypt(char* pri_buff, size_t pri_buff_len, char* ciphertext, size_t cipher_len) {
	SM2_KEY pri_key;

	if(read_sm2_pri_key(pri_buff, pri_buff_len, &pri_key) < 0) {
		return NULL;
	}
	// 此处创建，作为返回值返回，需要在外部释放
	char* plaintext = (char *)malloc(SM2_MAX_PLAINTEXT_SIZE);
	size_t plain_len;

	if (sm2_decrypt(&pri_key, (uint8_t *)ciphertext, cipher_len, (uint8_t *)plaintext, &plain_len) != 1) {
		fprintf(stderr, "[wasm][sm2] 解密失败 \n");
		free(plaintext); // 报错，提前释放内存
		return NULL;
	}
	plaintext[plain_len] = 0;
	return plaintext;
}

EM_PORT_API(char*) iasp_sm2_sign(char* pri_buff, size_t pri_buff_len, char* digest, size_t digest_len) {
	SM2_KEY pri_key;

	if(read_sm2_pri_key(pri_buff, pri_buff_len, &pri_key) < 0) {
		return NULL;
	}
	char* sig = (char *)malloc(SM2_MAX_SIGNATURE_SIZE);
	size_t sig_len;

	SM2_SIGN_CTX sign_ctx;

	sm2_sign_init(&sign_ctx, &pri_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_sign_update(&sign_ctx, (uint8_t *)digest, digest_len);
	sm2_sign_finish(&sign_ctx, (uint8_t *)sig, &sig_len);

	// 此处创建，作为返回值返回，需要在外部释放
	char* hex_sig = (char*)malloc(sig_len * 2 + 1);

	for (size_t i = 0; i < sig_len; i++) {
		sprintf(hex_sig + i * 2, "%02x", (unsigned char)sig[i]);
	}
	free(sig);
	return hex_sig;
}

EM_PORT_API(int) iasp_sm2_verify(char* pub_buff, size_t pub_buff_len, char* digest, size_t digest_len, char* sig, size_t siglen) {
	SM2_KEY pub_key;
	
	if(read_sm2_pub_key(pub_buff, pub_buff_len, &pub_key) < 0){
		return -1;
	}
	int ret;
	SM2_SIGN_CTX sign_ctx;

	sm2_verify_init(&sign_ctx, &pub_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	sm2_verify_update(&sign_ctx, (uint8_t *)digest, digest_len);

	if ((ret = sm2_verify_finish(&sign_ctx, (uint8_t *)sig, siglen)) != 1) {
		return -1;
	}
	return 0;
}

EM_PORT_API(int *) malloc_buf(int size) {
	int *buff = (int*)malloc(size);
	memset(buff, 0, size);
	return buff;
}

EM_PORT_API(void) free_buf(void* buf) {
	free(buf);
}