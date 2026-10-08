#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pqclean/ml-kem-512/api.h"
#include "pqclean/ml-kem-768/api.h"
#include "pqclean/ml-kem-1024/api.h"
#include "pqclean/ml-dsa-44/api.h"
#include "pqclean/ml-dsa-65/api.h"
#include "pqclean/ml-dsa-87/api.h"
#include <stdlib.h>
int PQCLEAN_randombytes(uint8_t*o,size_t n){FILE*f=fopen("/dev/urandom","rb");size_t r=fread(o,1,n,f);fclose(f);return r==n?0:-1;}
#define KEM(N,P) do{ static uint8_t pk[P##_CRYPTO_PUBLICKEYBYTES],sk[P##_CRYPTO_SECRETKEYBYTES],ct[P##_CRYPTO_CIPHERTEXTBYTES],a[64],b[64]; \
 int ok=P##_crypto_kem_keypair(pk,sk)==0&&P##_crypto_kem_enc(ct,a,pk)==0&&P##_crypto_kem_dec(b,ct,sk)==0&&!memcmp(a,b,P##_CRYPTO_BYTES); \
 ct[0]^=1; P##_crypto_kem_dec(b,ct,sk); int implicit=memcmp(a,b,P##_CRYPTO_BYTES)!=0; \
 printf("%s pk=%d ct=%d roundtrip=%s tampered_ct_differs=%s\n",N,P##_CRYPTO_PUBLICKEYBYTES,P##_CRYPTO_CIPHERTEXTBYTES,ok?"ok":"FAIL",implicit?"ok":"FAIL"); fails+=!ok||!implicit;}while(0)
#define DSA(N,P) do{ static uint8_t pk[P##_CRYPTO_PUBLICKEYBYTES],sk[P##_CRYPTO_SECRETKEYBYTES],sig[P##_CRYPTO_BYTES]; size_t sl=0; const uint8_t m[]="hello"; \
 int ok=P##_crypto_sign_keypair(pk,sk)==0&&P##_crypto_sign_signature(sig,&sl,m,5,sk)==0&&P##_crypto_sign_verify(sig,sl,m,5,pk)==0; \
 const uint8_t bad[]="hellp"; int rej=P##_crypto_sign_verify(sig,sl,bad,5,pk)!=0; \
 printf("%s pk=%d sig=%zu roundtrip=%s forged_rejected=%s\n",N,P##_CRYPTO_PUBLICKEYBYTES,sl,ok?"ok":"FAIL",rej?"ok":"FAIL"); fails+=!ok||!rej;}while(0)
int main(){int fails=0;
KEM("ML-KEM-512",PQCLEAN_MLKEM512_CLEAN);KEM("ML-KEM-768",PQCLEAN_MLKEM768_CLEAN);KEM("ML-KEM-1024",PQCLEAN_MLKEM1024_CLEAN);
DSA("ML-DSA-44",PQCLEAN_MLDSA44_CLEAN);DSA("ML-DSA-65",PQCLEAN_MLDSA65_CLEAN);DSA("ML-DSA-87",PQCLEAN_MLDSA87_CLEAN);
printf(fails?"FAILURES: %d\n":"ALL OK\n",fails);return fails;}
