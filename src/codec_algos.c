/*
** Name:        codec_algos.c
** Purpose:     Implementation of SQLite codec algorithms
** Author:      Ulrich Telle
** Created:     2020-02-02
** Copyright:   (c) 2006-2020 Ulrich Telle
** License:     MIT
*/

#include "cipher_common.h"
#if HAVE_CIPHER_AES_128_CBC || HAVE_CIPHER_AES_256_CBC || HAVE_CIPHER_SQLCIPHER
#include "rijndael.h"
#endif

#if HAVE_CIPHER_WOLF_AES_256_CBC || HAVE_CIPHER_WOLF_AES_128_CBC
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha256.h>
#endif


/*
** RC4 implementation
*/

SQLITE_PRIVATE void
sqlite3mcRC4(unsigned char* key, int keylen,
             unsigned char* textin, int textlen,
             unsigned char* textout)
{
  int i;
  int j;
  int t;
  unsigned char rc4[256];

  int a = 0;
  int b = 0;
  unsigned char k;

  for (i = 0; i < 256; i++)
  {
    rc4[i] = i;
  }
  j = 0;
  for (i = 0; i < 256; i++)
  {
    t = rc4[i];
    j = (j + t + key[i % keylen]) % 256;
    rc4[i] = rc4[j];
    rc4[j] = t;
  }

  for (i = 0; i < textlen; i++)
  {
    a = (a + 1) % 256;
    t = rc4[a];
    b = (b + t) % 256;
    rc4[a] = rc4[b];
    rc4[b] = t;
    k = rc4[(rc4[a] + rc4[b]) % 256];
    textout[i] = textin[i] ^ k;
  }
}

SQLITE_PRIVATE void
sqlite3mcGetMD5Binary(unsigned char* data, int length, unsigned char* digest)
{
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, data, length);
  MD5_Final(digest,&ctx);
}

SQLITE_PRIVATE void
sqlite3mcGetSHABinary(unsigned char* data, int length, unsigned char* digest)
{
  sha256(data, (unsigned int) length, digest);
}

#define MODMULT(a, b, c, m, s) q = s / a; s = b * (s - a * q) - c * q; if (s < 0) s += m

SQLITE_PRIVATE void
sqlite3mcGenerateInitialVector(int seed, unsigned char iv[16])
{
  unsigned char initkey[16];
  int j, q;
  int z = seed + 1;
  for (j = 0; j < 4; j++)
  {
    MODMULT(52774, 40692,  3791, 2147483399L, z);
    initkey[4*j+0] = 0xff &  z;
    initkey[4*j+1] = 0xff & (z >>  8);
    initkey[4*j+2] = 0xff & (z >> 16);
    initkey[4*j+3] = 0xff & (z >> 24);
  }
  sqlite3mcGetMD5Binary((unsigned char*) initkey, 16, iv);
}

#if HAVE_CIPHER_WOLF_AES_128_CBC || HAVE_CIPHER_WOLF_AES_256

SQLITE_PRIVATE void
sqlite3mcGetWolfMD5Binary(unsigned char* data, int length, unsigned char* digest)
{
  Md5 md5;
  wc_InitMd5(&md5);
  wc_Md5Update(&md5, data, length);
  wc_Md5Final(&md5, digest);
}

SQLITE_PRIVATE void
sqlite3mcGetWolfSHABinary(unsigned char* data, int length, unsigned char* digest)
{
  wc_Sha256 sha;
  wc_InitSha256(&sha);
  wc_Sha256Update(&sha, data, length);
  wc_Sha256Final(&sha, digest);
}

SQLITE_PRIVATE void
sqlite3mcGenerateWolfInitialVector(int seed, unsigned char iv[16])
{
  unsigned char initkey[16];
  int j, q;
  int z = seed + 1;
  for (j = 0; j < 4; j++)
  {
    MODMULT(52774, 40692,  3791, 2147483399L, z);
    initkey[4*j+0] = 0xff &  z;
    initkey[4*j+1] = 0xff & (z >>  8);
    initkey[4*j+2] = 0xff & (z >> 16);
    initkey[4*j+3] = 0xff & (z >> 24);
  }
  sqlite3mcGetWolfMD5Binary((unsigned char*) initkey, 16, iv);
}

#endif //HAVE_CIPHER_WOLF_AES_128_CBC || HAVE_CIPHER_WOLF_AES_256


#if HAVE_CIPHER_AES_128_CBC

SQLITE_PRIVATE int
sqlite3mcAES128(Rijndael* aesCtx, int page, int encrypt, unsigned char encryptionKey[KEYLENGTH_AES128],
                unsigned char* datain, int datalen, unsigned char* dataout)
{
  int rc = SQLITE_OK;
  unsigned char initial[16];
  unsigned char pagekey[KEYLENGTH_AES128];
  unsigned char nkey[KEYLENGTH_AES128+4+4];
  int keyLength = KEYLENGTH_AES128;
  int nkeylen = keyLength + 4 + 4;
  int j;
  int direction = (encrypt) ? RIJNDAEL_Direction_Encrypt : RIJNDAEL_Direction_Decrypt;
  int len = 0;

  for (j = 0; j < keyLength; j++)
  {
    nkey[j] = encryptionKey[j];
  }
  nkey[keyLength+0] = 0xff &  page;
  nkey[keyLength+1] = 0xff & (page >>  8);
  nkey[keyLength+2] = 0xff & (page >> 16);
  nkey[keyLength+3] = 0xff & (page >> 24);

  /* AES encryption needs some 'salt' */
  nkey[keyLength+4] = 0x73;
  nkey[keyLength+5] = 0x41;
  nkey[keyLength+6] = 0x6c;
  nkey[keyLength+7] = 0x54;

  sqlite3mcGetMD5Binary(nkey, nkeylen, pagekey);
  sqlite3mcGenerateInitialVector(page, initial);
  RijndaelInit(aesCtx, RIJNDAEL_Direction_Mode_CBC, direction, pagekey, RIJNDAEL_Direction_KeyLength_Key16Bytes, initial);
  if (encrypt)
  {
    len = RijndaelBlockEncrypt(aesCtx, datain, datalen*8, dataout);
  }
  else
  {
    len = RijndaelBlockDecrypt(aesCtx, datain, datalen*8, dataout);
  }

  /* It is a good idea to check the error code */
  if (len < 0)
  {
    /* AES: Error on encrypting. */
    rc = SQLITE_ERROR;
  }
  return rc;
}

#endif

#if HAVE_CIPHER_WOLF_AES_128_CBC

SQLITE_PRIVATE int
sqlite3mcWolfAES128(int page, int encrypt, unsigned char encryptionKey[KEYLENGTH_AES128],
                unsigned char* datain, int datalen, unsigned char* dataout)
{
  int rc = SQLITE_OK;
  unsigned char initial[16];
  unsigned char pagekey[KEYLENGTH_AES128];
  unsigned char nkey[KEYLENGTH_AES128+4+4];
  int keyLength = KEYLENGTH_AES128;
  int nkeylen = keyLength + 4 + 4;
  int j;
  int len = 0;

  for (j = 0; j < keyLength; j++)
  {
    nkey[j] = encryptionKey[j];
  }
  nkey[keyLength+0] = 0xff &  page;
  nkey[keyLength+1] = 0xff & (page >>  8);
  nkey[keyLength+2] = 0xff & (page >> 16);
  nkey[keyLength+3] = 0xff & (page >> 24);

  /* AES encryption needs some 'salt' */
  nkey[keyLength+4] = 0x73;
  nkey[keyLength+5] = 0x41;
  nkey[keyLength+6] = 0x6c;
  nkey[keyLength+7] = 0x54;

  sqlite3mcGetWolfMD5Binary(nkey, nkeylen, pagekey);
  sqlite3mcGenerateInitialVector(page, initial);

  if (encrypt)
  {
      printf("************** ENCRYPTING [");
      if (0 != wc_AesCbcEncryptWithKey(dataout, datain, datalen, pagekey, AES_128_KEY_SIZE, initial))
      {
          printf("FAILED]\n");
          rc = SQLITE_ERROR;
      }
      else
      {
          printf("SUCCESS]\n");
      }
  }
  else
  {
      printf("************** DECRYPTING [");
      if (0 != wc_AesCbcDecryptWithKey(dataout, datain, datalen, pagekey, AES_128_KEY_SIZE, initial))
      {
          printf("FAILED]\n");
          rc = SQLITE_ERROR;
      }
      else
      {
          printf("SUCCESS]\n");
      }
  }

  return rc;
}

#endif


#if HAVE_CIPHER_AES_256_CBC

SQLITE_PRIVATE int
sqlite3mcAES256(Rijndael* aesCtx, int page, int encrypt, unsigned char encryptionKey[KEYLENGTH_AES256],
                unsigned char* datain, int datalen, unsigned char* dataout)
{
  int rc = SQLITE_OK;
  unsigned char initial[16];
  unsigned char pagekey[KEYLENGTH_AES256];
  unsigned char nkey[KEYLENGTH_AES256+4+4];
  int keyLength = KEYLENGTH_AES256;
  int nkeylen = keyLength + 4 + 4;
  int j;
  int direction = (encrypt) ? RIJNDAEL_Direction_Encrypt : RIJNDAEL_Direction_Decrypt;
  int len = 0;

  for (j = 0; j < keyLength; j++)
  {
    nkey[j] = encryptionKey[j];
  }
  nkey[keyLength+0] = 0xff &  page;
  nkey[keyLength+1] = 0xff & (page >>  8);
  nkey[keyLength+2] = 0xff & (page >> 16);
  nkey[keyLength+3] = 0xff & (page >> 24);

  /* AES encryption needs some 'salt' */
  nkey[keyLength+4] = 0x73;
  nkey[keyLength+5] = 0x41;
  nkey[keyLength+6] = 0x6c;
  nkey[keyLength+7] = 0x54;

  sqlite3mcGetSHABinary(nkey, nkeylen, pagekey);
  sqlite3mcGenerateInitialVector(page, initial);
  RijndaelInit(aesCtx, RIJNDAEL_Direction_Mode_CBC, direction, pagekey, RIJNDAEL_Direction_KeyLength_Key32Bytes, initial);
  if (encrypt)
  {
    len = RijndaelBlockEncrypt(aesCtx, datain, datalen*8, dataout);
  }
  else
  {
    len = RijndaelBlockDecrypt(aesCtx, datain, datalen*8, dataout);
  }

  /* It is a good idea to check the error code */
  if (len < 0)
  {
    /* AES: Error on encrypting. */
    rc = SQLITE_ERROR;
  }
  return rc;
}

#endif

#if HAVE_CIPHER_WOLF_AES_256_CBC

SQLITE_PRIVATE int
sqlite3mcWolfAES256(int page, int encrypt, unsigned char encryptionKey[KEYLENGTH_AES256],
                unsigned char* datain, int datalen, unsigned char* dataout)
{
  int rc = SQLITE_OK;
  unsigned char initial[16];
  unsigned char pagekey[KEYLENGTH_AES256];
  unsigned char nkey[KEYLENGTH_AES256+4+4];
  int keyLength = KEYLENGTH_AES256;
  int nkeylen = keyLength + 4 + 4;
  int j;
  int len = 0;

  for (j = 0; j < keyLength; j++)
  {
    nkey[j] = encryptionKey[j];
  }
  nkey[keyLength+0] = 0xff &  page;
  nkey[keyLength+1] = 0xff & (page >>  8);
  nkey[keyLength+2] = 0xff & (page >> 16);
  nkey[keyLength+3] = 0xff & (page >> 24);

  /* AES encryption needs some 'salt' */
  nkey[keyLength+4] = 0x73;
  nkey[keyLength+5] = 0x41;
  nkey[keyLength+6] = 0x6c;
  nkey[keyLength+7] = 0x54;

  sqlite3mcGetWolfSHABinary(nkey, nkeylen, pagekey);
  sqlite3mcGenerateInitialVector(page, initial);

  if (encrypt)
  {
    printf("************** ENCRYPTING [");
    if (0 != wc_AesCbcEncryptWithKey(dataout, datain, datalen, pagekey, AES_256_KEY_SIZE, initial))
    {
        printf("FAILED]\n");
        rc = SQLITE_ERROR;
    }
    else
    {
        printf("SUCCESS]\n");
    }
  }
  else
  {
    printf("************** DECRYPTING [");
    if (0 != wc_AesCbcDecryptWithKey(dataout, datain, datalen, pagekey, AES_256_KEY_SIZE, initial))
    {
        printf("FAILED]\n");
        rc = SQLITE_ERROR;
    }
    else
    {
        printf("SUCCESS]\n");
    }
  }

  return rc;
}
#endif // HAVE_CIPHER_WOLF_AES_256_CBC

/* Check hex encoding */
SQLITE_PRIVATE int
sqlite3mcIsHexKey(const unsigned char* hex, int len)
{
  int j;
  for (j = 0; j < len; ++j)
  {
    unsigned char c = hex[j];
    if ((c < '0' || c > '9') && (c < 'A' || c > 'F') && (c < 'a' || c > 'f'))
    {
      return 0;
    }
  }
  return 1;
}

/* Convert single hex digit */
SQLITE_PRIVATE int
sqlite3mcConvertHex2Int(char c)
{
  return (c >= '0' && c <= '9') ? (c)-'0' :
    (c >= 'A' && c <= 'F') ? (c)-'A' + 10 :
    (c >= 'a' && c <= 'f') ? (c)-'a' + 10 : 0;
}

/* Convert hex encoded string to binary */
SQLITE_PRIVATE void
sqlite3mcConvertHex2Bin(const unsigned char* hex, int len, unsigned char* bin)
{
  int j;
  for (j = 0; j < len; j += 2)
  {
    bin[j / 2] = (sqlite3mcConvertHex2Int(hex[j]) << 4) | sqlite3mcConvertHex2Int(hex[j + 1]);
  }
}
