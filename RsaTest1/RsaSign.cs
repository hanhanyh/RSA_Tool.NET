using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace RsaTest1
{
    public class RsaSign
    {
        /// <summary>
        /// 生成签名
        /// </summary>
        /// <param name="str">需签名的数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encoding">编码格式 默认utf-8</param>
        /// <returns>签名后的值</returns>
        public static string Signature(string str, string privateKey, string encoding)
        {
            //SHA256withRSA
            //根据需要加签时的哈希算法转化成对应的hash字符节
            //byte[] bt = Encoding.GetEncoding("utf-8").GetBytes(str);
            byte[] bt = Encoding.GetEncoding(encoding).GetBytes(str);
            var sha256 = new SHA256CryptoServiceProvider();
            byte[] rgbHash = sha256.ComputeHash(bt);

            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.FromXmlString(privateKey);
            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");//此处是你需要加签的hash算法，需要和上边你计算的hash值的算法一致，不然会报错。
            byte[] inArray = formatter.CreateSignature(rgbHash);
            return Convert.ToBase64String(inArray);

        }
    }
}
