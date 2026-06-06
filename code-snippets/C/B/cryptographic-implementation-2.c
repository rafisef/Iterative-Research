using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
public class TripleDESEncryption
{
    public static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
    {
        using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
        {
            tdes.Key = key;
            tdes.IV = iv;
            
            ICryptoTransform encryptor = tdes.CreateEncryptor(tdes.Key, tdes.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }
    }
}