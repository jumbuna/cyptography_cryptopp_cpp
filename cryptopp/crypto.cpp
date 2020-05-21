//
//  crypto.cpp
//  cryptopp
//
//  Created by jumbuna on 18/05/2020.
//  Copyright © 2020 jumbuna. All rights reserved.
//

#include "crypto.hpp"
#include <iostream>
#include <cstddef>
#include <string>
#include <fstream>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/md5.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/rsa.h>

crypto::crypto(std::string str): str(str) {
//    filesource();
//    stringsource();
//    randomnumbersource();
//    sha256();
//    md5();
//    symmetrical();
//    getkeyfromsource();
//    asymmetrical();
    getKeysfromsource();
//    usingexternalkeys();
}

void crypto::filesource() {
    std::string s;
    std::ifstream source {"/users/pro/desktop/hello.txt"};
    CryptoPP::FileSource filesrc { source, true, new CryptoPP::HexEncoder( new CryptoPP::StringSink(s)) };
    std::cout << s << std::endl;
    source.close();
}

void crypto::stringsource() {
    std::ofstream dstntn { "/users/pro/desktop/hello2.txt"};
    CryptoPP::StringSource { "hello too!", true, new CryptoPP::FileSink(dstntn)};
    std::cout << "written" << std::endl;
    dstntn.close();
}

void crypto::randomnumbersource() {
    CryptoPP::AutoSeededRandomPool rndpool;
    std::string s;
    CryptoPP::RandomNumberSource { rndpool, 5, true, new CryptoPP::StringSink{s}};
    std::cout << s << std::endl;
}

void crypto::sha256() {
    CryptoPP::SHA256 hash;
    CryptoPP::FileSource { "/users/pro/desktop/hello2.txt", true, new CryptoPP::HashFilter {hash, new CryptoPP::HexEncoder { new CryptoPP::FileSink(std::cout)}}};
    std::cout << std::endl;
}

void crypto::md5() {
    CryptoPP::MD5 hash;
    CryptoPP::StringSource { "hello too!", true, new CryptoPP::HashFilter {hash, new CryptoPP::HexEncoder { new CryptoPP::FileSink(std::cout)}}};
    std::cout << std::endl;
}

void crypto::symmetrical() {
    CryptoPP::AutoSeededRandomPool rndpul;
    CryptoPP::SecByteBlock key { CryptoPP::AES::DEFAULT_KEYLENGTH };
    rndpul.GenerateBlock(key, key.size());
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    rndpul.GenerateBlock(iv, iv.size());
//    encryption
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key, key.size(), iv);
    std::string dest;
    CryptoPP::StringSource(str, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::HexEncoder( new CryptoPP::StringSink(dest))));
    std::cout << dest << std::endl;
//    decryption
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key, key.size(), iv);
    std::string raw;
    CryptoPP::StringSource(dest, true, new CryptoPP::HexDecoder(new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(raw))));
    std::cout << raw << std::endl;
    //store key & iv
    std::string skey, siv;
    CryptoPP::ArraySource(key.data(), key.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(skey)));
    CryptoPP::StringSource(iv.data(), iv.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(siv)));
    std::ofstream output("/users/pro/desktop/encdata.txt");
    output << skey << std::endl;
    output << siv << std::endl;
    output << dest << std::endl;
    output.flush();
    output.close();
}

void crypto::getkeyfromsource() {
    std::ifstream input("/users/pro/desktop/encdata.txt");
    std::string key, iv, cipher, ns, k;
    std::getline(input, key);
    std::getline(input, iv);
    std::getline(input, cipher);
    
    CryptoPP::SecByteBlock bkey(CryptoPP::AES::DEFAULT_KEYLENGTH), biv(CryptoPP::AES::BLOCKSIZE);
    CryptoPP::StringSource(key, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(bkey, bkey.size())));
    CryptoPP::StringSource(iv, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(biv, biv.size())));
    CryptoPP::StringSource(cipher, true, new CryptoPP::HexDecoder( new CryptoPP::StringSink(ns)));
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(bkey, bkey.size(), biv);
    
    CryptoPP::ArraySource(ns, true, new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(k)));
    
    input.close();
    std::cout << k << std::endl;
}

void crypto::asymmetrical() {
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::RSA::PrivateKey privatekey;
    privatekey.GenerateRandomWithKeySize(rnd, 1024);
    CryptoPP::RSA::PublicKey publickey { privatekey };
    CryptoPP::ByteQueue privateQ, publicQ;
    privatekey.Save(privateQ);
    publickey.Save(publicQ);
    std::string raw;
//    encryption
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publickey);
    CryptoPP::StringSource(str, true, new CryptoPP::PK_EncryptorFilter(rnd, encryptor, new CryptoPP::HexEncoder( new CryptoPP::FileSink("/users/pro/desktop/pkenc.txt"))));
//    decryption
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privatekey);
    CryptoPP::AutoSeededRandomPool rnd2;
    CryptoPP::FileSource("/users/pro/desktop/pkenc.txt", true, new CryptoPP::HexDecoder( new CryptoPP::PK_DecryptorFilter(rnd2,decryptor, new CryptoPP::StringSink(raw))));
    CryptoPP::HexEncoder prvfile( new CryptoPP::FileSink( "/users/pro/desktop/private.key"));
    CryptoPP::HexEncoder pubfile(new CryptoPP::FileSink ("/users/pro/desktop/public.key"));
    publicQ.CopyTo(pubfile);
    privateQ.CopyTo(prvfile);
    std::cout << raw << std::endl;
}

void crypto::getKeysfromsource() {
    CryptoPP::AutoSeededRandomPool rnd;
    std::string key;
    CryptoPP::ByteQueue prvtq, pblq;
    CryptoPP::FileSource file("/users/pro/desktop/public.key", true, new CryptoPP::HexDecoder( new CryptoPP::Redirector(prvtq)));
    CryptoPP::RSA::PublicKey publickey;
    publickey.Load(prvtq);
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publickey);
    CryptoPP::StringSource("niaje msee", true, new CryptoPP::PK_EncryptorFilter(rnd, encryptor, new CryptoPP::HexEncoder( new CryptoPP::FileSink("/users/pro/desktop/swa.txt"))));
    std::cout << "encryption complete" << std::endl;
}

void crypto::usingexternalkeys() {
    CryptoPP::AutoSeededRandomPool randompool;
    CryptoPP::ByteQueue q1, q2;
    CryptoPP::FileSource("/users/pro/desktop/javaprivate.txt", true, new CryptoPP::HexDecoder(new CryptoPP::Redirector(q1)));
    CryptoPP::FileSource("/users/pro/desktop/javapublic.txt", true,  new CryptoPP::HexDecoder(new CryptoPP::Redirector(q2)));
    CryptoPP::RSA::PrivateKey privatekey;
    CryptoPP::RSA::PublicKey publickey;
    privatekey.Load(q1);
    publickey.Load(q2);
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publickey);
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privatekey);
    std::string raw = "how are you", cipher, decipher;
    CryptoPP::StringSource(raw, true, new CryptoPP::PK_EncryptorFilter(randompool, encryptor, new CryptoPP::StringSink(cipher)));
    CryptoPP::StringSource(cipher, true, new CryptoPP::PK_DecryptorFilter(randompool, decryptor, new CryptoPP::StringSink(decipher)));
    
    std::cout << decipher << std::endl;
}
