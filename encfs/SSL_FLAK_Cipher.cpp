/*****************************************************************************
 * Author:   Dmitry Falko <dfalko@digiflak.com>
 *
 *****************************************************************************
 * Copyright (c) 2015, Dmitry Falko
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "SSL_FLAK_Cipher.h"

#include <string.h>
#include <sys/mman.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "Mutex.h"

#define PROTOCOL_BYTES (5)

using namespace rel;

const int MAX_KEYLENGTH = 32;  // in bytes (256 bit)
const int MAX_IVLENGTH = 16;   // 128 bit (AES block size, Blowfish has 64)
const int KEY_CHECKSUM_BYTES = 4;

static Interface FlakInterface("flak/aes", 1, 0, 0);

class SSLKey : public AbstractCipherKey {
public:
    pthread_mutex_t mutex;

    unsigned int keySize;  // in bytes
    unsigned int ivLength;

    // key data is first _keySize bytes,
    // followed by iv of _ivLength bytes,
    unsigned char *buffer;

    EVP_CIPHER_CTX block_enc;
    EVP_CIPHER_CTX block_dec;
    EVP_CIPHER_CTX stream_enc;
    EVP_CIPHER_CTX stream_dec;

    HMAC_CTX mac_ctx;

    SSLKey(int keySize, int ivLength);
    ~SSLKey();
};

SSL_FLAK_Cipher::SSL_FLAK_Cipher(const rel::Interface &iface, const rel::Interface &realIface,
                                 const EVP_CIPHER *blockCipher, const EVP_CIPHER *streamCipher, int keyLength):
        SSL_Cipher(iface, realIface, blockCipher, streamCipher, keyLength)
{
    this->iface = iface;
    this->realIface = realIface;
    this->_blockCipher = blockCipher;
    this->_streamCipher = streamCipher;
    this->_keySize = keyLength;
    this->_ivLength = EVP_CIPHER_iv_length(_blockCipher);
}

SSL_FLAK_Cipher::~SSL_FLAK_Cipher()
{

}

CipherKey SSL_FLAK_Cipher::readKey(const unsigned char *data, const CipherKey &masterKey, bool checkKey) {
    shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(masterKey);
    rAssert(mk->keySize == _keySize);

    unsigned char tmpBuf[MAX_KEYLENGTH + MAX_IVLENGTH];

    // First N bytes are checksum bytes.
    unsigned int checksum = 0;
    for (int i = 0; i < KEY_CHECKSUM_BYTES; ++i)
        checksum = (checksum << 8) | (unsigned int)data[i];

    memcpy(tmpBuf, data + KEY_CHECKSUM_BYTES, _keySize + _ivLength);
    keyDecode(tmpBuf, _keySize + _ivLength, checksum, masterKey);

    // check for success
    unsigned int checksum2 = MAC_32(tmpBuf, _keySize + _ivLength, masterKey);
    if (checksum2 != checksum && checkKey) {
        rDebug("checksum mismatch: expected %u, got %u", checksum, checksum2);
        rDebug("on decode of %i bytes", _keySize + _ivLength);
        memset(tmpBuf, 0, sizeof(tmpBuf));
        return CipherKey();
    }

    shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

    memcpy(key->buffer, tmpBuf, _keySize + _ivLength);
    memset(tmpBuf, 0, sizeof(tmpBuf));

    initKey(key, _blockCipher, _streamCipher, _keySize);

    return key;
}

void SSL_FLAK_Cipher::writeKey(const CipherKey &ckey, unsigned char *data, const CipherKey &masterKey)
{
    shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
    rAssert(key->keySize == _keySize);
    rAssert(key->ivLength == _ivLength);

    shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(masterKey);
    rAssert(mk->keySize == _keySize);
    rAssert(mk->ivLength == _ivLength);

    unsigned char tmpBuf[MAX_KEYLENGTH + MAX_IVLENGTH];

    int bufLen = _keySize + _ivLength;
    memcpy(tmpBuf, key->buffer, bufLen);

    unsigned int checksum = MAC_32(tmpBuf, bufLen, masterKey);

    keyEncode(tmpBuf, bufLen, checksum, masterKey);
    memcpy(data + KEY_CHECKSUM_BYTES, tmpBuf, bufLen);

    // first N bytes contain HMAC derived checksum..
    for (int i = 1; i <= KEY_CHECKSUM_BYTES; ++i) {
        data[KEY_CHECKSUM_BYTES - i] = checksum & 0xff;
        checksum >>= 8;
    }

    memset(tmpBuf, 0, sizeof(tmpBuf));
}

bool SSL_FLAK_Cipher::keyDecode(unsigned char *in, int len, uint64_t iv64, const CipherKey &key) const
{
    /*
     * Decode VolumeKey by Flak
     */
    rDebug("decoding key");
    int sockfd, portno, n;
    int rec_len = 0;
    struct sockaddr_in serv_addr;
    unsigned char buf[PROTOCOL_BYTES + MAX_KEYLENGTH + MAX_IVLENGTH];

    buf[0] = 0xDF;
    buf[1] = 0x00;
    buf[2] = 0x04;
    *((uint16_t *)(buf + 3)) = (uint16_t) len;
    memcpy(buf + 5, in, len);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        rDebug("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(8212);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
        rDebug("ERROR connecting");
        return false;
    }


    if(send(sockfd, buf, len + PROTOCOL_BYTES, 0) < 0) {
        rDebug("ERROR sending");
        return false;
    }

    /* receive answer*/
    while(rec_len < len + PROTOCOL_BYTES) {
        int rec = 0;

        rec = recv(sockfd, buf, len + PROTOCOL_BYTES, 0);
        if(rec < 0 ) {
            rDebug("ERROR sending");
            return false;
        }
        rec_len += rec;
    }

    memcpy(in, buf + PROTOCOL_BYTES, len);

    return true;
}

bool SSL_FLAK_Cipher::keyEncode(unsigned char *in, int len, uint64_t iv64, const CipherKey &key) const
{
    /*
     * Encode VolumeKey by Flak
     */
    rDebug("encoding key");
    int sockfd, portno, n;
    int rec_len;
    struct sockaddr_in serv_addr;
    unsigned char buf[PROTOCOL_BYTES + MAX_KEYLENGTH + MAX_IVLENGTH];

    buf[0] = 0xDF;
    buf[1] = 0x00;
    buf[2] = 0x02;
    *((uint16_t *)(buf + 3)) = (uint16_t) len;
    memcpy(buf + 5, in, len);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        rDebug("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(8212);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
        rDebug("ERROR connecting");
        return false;
    }


    if(send(sockfd, buf, len + PROTOCOL_BYTES, 0) < 0) {
        rDebug("ERROR sending");
        return false;
    }

    /* receive answer*/
    while(rec_len < len + PROTOCOL_BYTES) {
        int rec = 0;

        rec = recv(sockfd, buf, len + PROTOCOL_BYTES, 0);
        if(rec < 0 ) {
            rDebug("ERROR sending");
            return false;
        }
        rec_len += rec;
    }

    memcpy(in, buf + PROTOCOL_BYTES, len);

    return true;
}


static Range FlakAESKeyRange(128, 256, 64);
static Range FlakAESBlockRange(64, 4096, 16);

static shared_ptr<Cipher> NewFlakAESCipher(const Interface &iface, int keyLen) {
    if (keyLen <= 0) keyLen = 192;

    keyLen = FlakAESKeyRange.closest(keyLen);

    const EVP_CIPHER *blockCipher = 0;
    const EVP_CIPHER *streamCipher = 0;

    switch (keyLen) {
        case 128:
            blockCipher = EVP_aes_128_cbc();
            streamCipher = EVP_aes_128_cfb();
            break;

        case 192:
            blockCipher = EVP_aes_192_cbc();
            streamCipher = EVP_aes_192_cfb();
            break;

        case 256:
        default:
            blockCipher = EVP_aes_256_cbc();
            streamCipher = EVP_aes_256_cfb();
            break;
    }

    return shared_ptr<Cipher>(new SSL_FLAK_Cipher(iface, FlakInterface, blockCipher,
                                             streamCipher, keyLen / 8));
}

static bool FlakAES_Cipher_registered =
        Cipher::Register("Flak_AES", "16 byte block cipher with keystorage on Flak", FlakInterface, FlakAESKeyRange,
                         FlakAESBlockRange, NewFlakAESCipher);