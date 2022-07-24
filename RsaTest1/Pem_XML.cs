using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;

namespace RsaTest1
{
    public class Pem_XML
    {



        public static string privatekeyConent = @" 
MIICWwIBAAKBgQCkhcrmb6Gv6vdO+/ZAVj/cxsP1NR5qnKrM6+nrorYJpW1GWlJk
lDVLSsxJWaxmSKXD1l6UFmyOqkQsI6Lz9xKS65HrvgnAu+4rzdQjkrEf5KgnUfiS
widwM1AQipK2fuPfGxH7oP7LYXw0cQPvJgngLxDnxPxU8fgzab8huL3hxwIDAQAB
AoGAOjnHl0pGtNW5dNCjVB2yOFZ4H54PB7gukpuji+tn9X4AcHei1UnGmsD8D7GW
3BQ15ltF2a8d+Fe2DNEH6MO2ZIqFBFcjLoYxHx/aC1LEplJtvuTN5GerJNkaSSlo
0K0A+tTKaQQSbkwXL6vjIw4yLzUFgJz7IxIyD6NWjqK6wQECQQDnESXEmSmfZy9v
4NmJqV+3H3+6agq8ikIFUu0IfMhvxLF7Svlvq4o2KfXnKZZvcj6JJ59ApJs3A++B
PyARMqmHAkEAtkZ28gGDpgMkLdCNgjLObRut8YZDFmr0bfiFrXZwgBTqUivTY5hp
ExEgarJWOeafB6wTAKuFONVid1fUsjwVwQJAWXytmM8MbJyEpZp6BTNgS0ZarDJH
SC9vVCqCfAf/hDGz3qDxq0rO8x0bC9RyW2TuTSXYKivVpN/UUMTGwYJSXwJAOp7c
4CX2heyatRVOfWIDm3l8bqHEb7BEHh4AN/JQahDP709i87Pvjw9CAq6KJqLx4FDJ
57xB4y5VNZaMtCm4wQJAdV+x7k6nIjvc/a3RPDpH31bOM4oN1BNTZjwE1XhWlkyI
+o2YdSg82U8swhaqNe5RoTqTw9G1oVxaVl+Gx1vwOQ==
 ";
        public static string publickeyConent = @"
 
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkhcrmb6Gv6vdO+/ZAVj/cxsP1
NR5qnKrM6+nrorYJpW1GWlJklDVLSsxJWaxmSKXD1l6UFmyOqkQsI6Lz9xKS65Hr
vgnAu+4rzdQjkrEf5KgnUfiSwidwM1AQipK2fuPfGxH7oP7LYXw0cQPvJgngLxDn
xPxU8fgzab8huL3hxwIDAQAB
 

";  RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

        //string privatekeyXml = ConvertToXmlPrivateKey(RSAalg, privatekeyConent);//把java的私钥转换成.net的xml格式

        //string publickeyXml = ConvertToXmlPublicJavaKey(RSAalg, publickeyConent);//把java的公钥转换成.net的xml格式
        /// <summary>
        ///获取pem私钥正文内容
        /// </summary>
        /// <param name="filePath">私钥证书路径</param>
        /// <returns></returns>
        public static string privateKeyContent(string filePath)
        {

            string content = File.ReadAllText(filePath, Encoding.ASCII);//获取pem证书完整内容
            if (string.IsNullOrEmpty(content))
            {
                throw new ArgumentNullException("pemFileConent", "This arg cann't be empty.");
            }
            string privatekeyConent = content.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\n", "").Replace("\r", "");//去掉证书的头部和尾部
            return privatekeyConent;
        }

        /// <summary>
        ///获取pem公钥正文内容
        /// </summary>
        /// <param name="filePath">私钥证书路径</param>
        /// <returns></returns>
        public static string publicKeyContent(string filePath)
        {

            string content = File.ReadAllText(filePath, Encoding.ASCII);//获取pem证书完整内容

            if (string.IsNullOrEmpty(content))
            {
                throw new ArgumentNullException("pemFileConent", "This arg cann't be empty.");
            }
            string publickeyConent = content.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "");//去掉证书的头部和尾部
            return publickeyConent;

        }

        /// <summary>
        /// 把java的私钥转换成.net的xml格式
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="privateJavaKey"></param>
        /// <returns></returns>
        public static string ConvertToXmlPrivateKey(string privateJavaKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateJavaKey));
            string xmlPrivateKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
            Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
            return xmlPrivateKey;
        }

        /// <summary>
        /// 把java的公钥转换成.net的xml格式
        /// </summary>
        /// <param name="privateKey">java提供的第三方公钥</param>
        /// <returns></returns>
        public static string ConvertToXmlPublicJavaKey(string publicJavaKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicJavaKey));
            string xmlpublicKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
            Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
            return xmlpublicKey;
        }
    }
}
