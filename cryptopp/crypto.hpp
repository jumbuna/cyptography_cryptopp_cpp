//
//  crypto.hpp
//  cryptopp
//
//  Created by jumbuna on 18/05/2020.
//  Copyright © 2020 jumbuna. All rights reserved.
//

#ifndef crypto_hpp
#define crypto_hpp

#include <cryptopp/cryptlib.h>

struct crypto {
    crypto(std::string str);
    void sha256();
    void md5();
    void symmetrical();
    void asymmetrical();
    void filesource();
    void stringsource();
    void randomnumbersource();
    void getkeyfromsource();
    void getKeysfromsource();
    void usingexternalkeys();
private:
    std::string str;
};

#endif /* crypto_hpp */
