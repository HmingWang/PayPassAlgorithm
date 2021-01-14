import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Map;

import com.whaim.*;
import org.bouncycastle.util.encoders.Hex;

public class Application {

    public static void main(String[] args) throws Exception {
        System.out.println("==================================【RSA】========================================");
        Map<String, String> keyMap = RSAUtils.createKeys(512);
        String publicKey = keyMap.get("publicKey");
        String privateKey = keyMap.get("privateKey");
        System.out.println("公钥: \n\r" + publicKey);
        System.out.println("私钥： \n\r" + privateKey);

        System.out.println("公钥加密——私钥解密");
        String str = "站在大明门前守卫的禁卫军，事先没有接到\n" + "有关的命令，但看到大批盛装的官员来临，也就\n" + "以为确系举行大典，因而未加询问。进大明门即\n" + "为皇城。文武百官看到端门午门之前气氛平静，\n" + "城楼上下也无朝会的迹象，既无几案，站队点名\n" + "的御史和御前侍卫“大汉将军”也不见踪影，不免\n"
                + "心中揣测，互相询问：所谓午朝是否讹传？";
        System.out.println("\r明文：\r\n" + str);
        System.out.println("\r明文大小：\r\n" + str.getBytes().length);
        String encodedData = RSAUtils.publicEncrypt(str, RSAUtils.getPublicKey(publicKey));  //传入明文和公钥加密,得到密文
        System.out.println("密文：\r\n" + encodedData);
        String decodedData = RSAUtils.privateDecrypt(encodedData, RSAUtils.getPrivateKey(privateKey)); //传入密文和私钥,得到明文
        System.out.println("解密后文字: \r\n" + decodedData);


        System.out.println("==================================【DSA】========================================");

        String data = "31231231231231";

        //创建秘钥生成器
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair keypair = kpg.generateKeyPair();//生成秘钥对
        DSAPublicKey publickey = (DSAPublicKey)keypair.getPublic();
        DSAPrivateKey privatekey = (DSAPrivateKey)keypair.getPrivate();

        //签名和验证
        //签名
        Signature sign = Signature.getInstance("SHA1withDSA");
        sign.initSign(privatekey);//初始化私钥，签名只能是私钥
        sign.update(data.getBytes());//更新签名数据
        byte[] b = sign.sign();//签名，返回签名后的字节数组
        System.out.println(b.length);

        //验证
        sign.initVerify(publickey);//初始化公钥，验证只能是公钥
        sign.update(data.getBytes());//更新验证的数据
        boolean result = sign.verify(b);//签名和验证一致返回true  不一致返回false
        System.out.println(result);

        System.out.println("==================================【SM2】========================================");
        //生成密钥对
        SM2Utils.generateKeyPair();

        String plainText = "3123123123123123123123123123131231231231231231231231231231";
        byte[] sourceData = plainText.getBytes();

        //下面的秘钥可以使用generateKeyPair()生成的秘钥内容
        // 国密规范正式私钥
        String prik = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
        // 国密规范正式公钥
        String pubk = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";

        System.out.println("加密: ");
        String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
        System.out.println(cipherText);
        System.out.println("解密: ");
        plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(cipherText)));
        System.out.println(plainText);

        System.out.println("==================================【SM3】========================================");
        byte[] md = new byte[32];
        byte[] msg1 = "ererfeiisgod".getBytes();
        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg1, 0, msg1.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        System.out.println(s.toUpperCase());

        System.out.println("==================================【SM4】========================================");
        plainText = "ererfeiisgod";

        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = "JeF8U9wHFOMfs2Y8";
        sm4.hexString = false;

        System.out.println("ECB模式加密");
        cipherText = sm4.encryptData_ECB(plainText);
        System.out.println("密文: " + cipherText);
        System.out.println("");

        plainText = sm4.decryptData_ECB(cipherText);
        System.out.println("明文: " + plainText);
        System.out.println("");

        System.out.println("CBC模式加密");
        sm4.iv = "UISwD9fW6cFh9SNS";
        cipherText = sm4.encryptData_CBC(plainText);
        System.out.println("密文: " + cipherText);
        System.out.println("");

        plainText = sm4.decryptData_CBC(cipherText);
        System.out.println("明文: " + plainText);

        System.out.println("CBC模式解密");
        System.out.println("密文：4esGgDn/snKraRDe6uM0jQ==");
        String cipherText2 = "4esGgDn/snKraRDe6uM0jQ==";
        plainText = sm4.decryptData_CBC(cipherText2);
        System.out.println("明文: " + plainText);
    }
}
