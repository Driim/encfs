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


#ifndef ENCFS_SSL_FLAK_CIPHER_H
#define ENCFS_SSL_FLAK_CIPHER_H

#include "SSL_Cipher.h"

class SSL_FLAK_Cipher: public SSL_Cipher {

    rel::Interface iface;
    rel::Interface realIface;
    const EVP_CIPHER *_blockCipher;
    const EVP_CIPHER *_streamCipher;
    unsigned int _keySize;  // in bytes
    unsigned int _ivLength;

    virtual bool keyDecode(unsigned char *in, int len, uint64_t iv64,
                              const CipherKey &key) const;
    virtual bool keyEncode(unsigned char *in, int len, uint64_t iv64,
                           const CipherKey &key) const;

public:

    SSL_FLAK_Cipher(const rel::Interface &iface, const rel::Interface &realIface,
               const EVP_CIPHER *blockCipher, const EVP_CIPHER *streamCipher,
               int keyLength);
    virtual ~SSL_FLAK_Cipher();

    /*
     * Using Flak to encrypt and decrypt volume key
     */
    virtual CipherKey readKey(const unsigned char *data,
                              const CipherKey &encodingKey, bool checkKey);
    virtual void writeKey(const CipherKey &key, unsigned char *data,
                          const CipherKey &encodingKey);
};


#endif //ENCFS_SSL_FLAK_CIPHER_H
