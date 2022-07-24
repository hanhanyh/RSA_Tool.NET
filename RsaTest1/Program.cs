using Microsoft.SqlServer.Server;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RsaTest1
{
    class Program
    {
        static void Main(string[] args)

        {
            string publickey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtu35CrUSDnZlg6JVXy1qjJ8Bv
9NZZo64h5dyEkfFv4fRbUSMIh4jvq97ISYCcFCwZd/5hfucMO3WRM3NPryimvpTx
o7sVuOGKWnetomd0EhG12GdAa2aufANXBSUEdSezlqhTFth9mhqHHh9XfR95TeVJ
w8qZV0Wd3yrM+S3CyQIDAQAB";
            //1024位 pkcs8  RSA1/RSA2都可
            string privkey = @"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAK27fkKtRIOdmWDo
lVfLWqMnwG/01lmjriHl3ISR8W/h9FtRIwiHiO+r3shJgJwULBl3/mF+5ww7dZEz
c0+vKKa+lPGjuxW44Ypad62iZ3QSEbXYZ0BrZq58A1cFJQR1J7OWqFMW2H2aGoce
H1d9H3lN5UnDyplXRZ3fKsz5LcLJAgMBAAECgYBtY73nW9PlD2mQ5EGMiyVhz9jS
ZZZF0NMG0wXbj003Rk2m5dqqNzTYvB5FfEp3fBgcXTqVxuLSB+pJ59x2UvLDqJi0
QEtqiY2rY6Tn2juH5RMdXKDuv6WH9m6JR3vHxM+HqMh+bA39RFGeijCsOoYaP3L5
dBIEJKlS4PVTF8dcEQJBAORK9nKspFNm3XdDfc/O46i/d8IcLdyLbTqefXfoNo4A
THoIpj6DPFHgObVbrpeaj84tDVwQOTV4+jVKd74aHv0CQQDC0VfNUeXhFSAokReH
Fkoks29Q3I46L2l00gUbxphvVO+QA3fizwcJ9fsS0lkHDg4JMDsFfnuPoO4esVOO
Gwq9AkEAxeguie8cbajpKPD7amFifvGtcjtXjq/YO08WWhKW6LddlRVWeS7v5dLK
dGxMiOTW8degk0UFM1PzJKuv7r9aSQJAF3E1TYGDVdhC7F65JAoslcn5pRNFEf9O
gz4aW0NEaHEh+oRQUrxyrmIo+hTRnaW1Tqm9EGYt3BSTUqIn2burSQJAQ5V9Jpym
B98s/r1ZtG/d+cLWywJk6CYvjQnhHKOHcmkTYMheM8HWGt3gGe045kkrcKSTZRh5
lkqwLl7eSzR+9Q==";

            RSATool t = new RSATool();
            var q = t.DecryptByPublicKey("fvwb45hxzNbJKA64uDAxpmV0SSjmvSIJxfwQ0X6gpRG1ZYyqYgYZF5xLqFGCzh+r2ZHoeH+yVs+SoVdJ19FyPVuCBkE5YMGSX+bWRUn9AWrmrSje/G0LXWHKLWmECBTaXZF744Nrc4/Q7CknkcWRABe7m6h8ijsEWR9PknkB/as=", privkey, false);
            var p = t.EncryptByKey("你好呀呀", publickey, true);
            //sha1验签
            bool verify = t.ValidationPublicKey("RSA公私钥加密解密",
                  "AFIkVAMNOvyLqSfV6HgbxoBOSp1XkNo7XjH88OTsnj3Tx5+UqXujydQSDVHU9it4/WTonS3OjQ5venqBs7sbZjzEIwCgOc86DIzHITxO2c57swk8AfUfy6CrEyIEvqonIc6RkzkoH7xe9tL7PakqLQSeydpgFdB7+CpOcWKQ1bs=",
                 publickey);
            //sha256验证签
            bool verify256 = t.ValidationPublicKey("你好",
                 "NjIlqQrCGAehqGTQdeVgdf7+rU94dyKjZj1D1yi5nvibbjfXmbgdfJ9btMVnzPhpMtwAXRQADVe+wqk8ZdaGXvJSnX4R3hmr7rol7qwU3cHYfJ3cckpyv/ABVAgFycBG5tKvvWoRNsOYnFKBJRCzySz+Fx91CtO+e9uzygEwj3M=",
                publickey);

            //
            string verify256sign = t.SignByPrivateKey("RS你好呀呀", privkey) ;

        }
    }
}
