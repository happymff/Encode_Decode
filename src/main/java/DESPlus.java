import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.*;
import javax.crypto.*;

/**
 * web密码加密
 * <p>
 * Created by chentong on 14-12-1.
 */
public class DESPlus {

    private static String strDefaultKey = "losttime";

    private Cipher encryptCipher = null;

    private Cipher decryptCipher = null;

    /**
     * 将byte数组转换为表示16进制值的字符串， 如：byte[]{8,18}转换为：0813， 和public static byte[] hexStr2ByteArr(String strIn) 互为可逆的转换过程
     *
     * @param arrB 需要转换的byte数组
     * @return 转换后的字符串
     * @throws Exception 本方法不处理任何异常，所有异常全部抛出
     */
    public static String byteArr2HexStr(byte[] arrB) throws Exception {
        int iLen = arrB.length;
        // 每个byte用两个字符才能表示，所以字符串的长度是数组长度的两倍
        StringBuffer sb = new StringBuffer(iLen * 2);
        for (int i = 0; i < iLen; i++) {
            int intTmp = arrB[i];
            // 把负数转换为正数
            while (intTmp < 0) {
                intTmp = intTmp + 256;
            }
            // 小于0F的数需要在前面补0
            if (intTmp < 16) {
                sb.append("0");
            }
            sb.append(Integer.toString(intTmp, 16));
        }
        return sb.toString();
    }

    /**
     * 将表示16进制值的字符串转换为byte数组， 和public static String byteArr2HexStr(byte[] arrB) 互为可逆的转换过程
     *
     * @param strIn 需要转换的字符串
     * @return 转换后的byte数组
     * @throws Exception 本方法不处理任何异常，所有异常全部抛出
     */
    public static byte[] hexStr2ByteArr(String strIn) throws Exception {
        byte[] arrB = strIn.getBytes();
        int iLen = arrB.length;

        // 两个字符表示一个字节，所以字节数组长度是字符串长度除以2
        byte[] arrOut = new byte[iLen / 2];
        for (int i = 0; i < iLen; i = i + 2) {
            String strTmp = new String(arrB, i, 2);
            arrOut[i / 2] = (byte) Integer.parseInt(strTmp, 16);
        }
        return arrOut;
    }

    /**
     * 默认构造方法，使用默认密钥
     *
     * @throws Exception
     */
    public DESPlus() throws Exception {
        this(strDefaultKey);
    }

    /**
     * 指定密钥构造方法
     *
     * @param strKey 指定的密钥
     * @throws Exception
     */
    public DESPlus(String strKey) throws Exception {

        Key key = getKey(strKey.getBytes());

        encryptCipher = Cipher.getInstance("DES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);

        decryptCipher = Cipher.getInstance("DES");
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
    }

    /**
     * 加密字节数组
     *
     * @param arrB 需加密的字节数组
     * @return 加密后的字节数组
     * @throws Exception
     */
    public byte[] encrypt(byte[] arrB) throws Exception {
        return encryptCipher.doFinal(arrB);
    }

    /**
     * 加密字符串
     *
     * @param strIn 需加密的字符串
     * @return 加密后的字符串
     * @throws Exception
     */
    public String encrypt(String strIn) throws Exception {
        return byteArr2HexStr(encrypt(strIn.getBytes()));
    }

    /**
     * 解密字节数组
     *
     * @param arrB 需解密的字节数组
     * @return 解密后的字节数组
     * @throws Exception
     */
    public byte[] decrypt(byte[] arrB) throws Exception {
        return decryptCipher.doFinal(arrB);
    }

    /**
     * 解密字符串
     *
     * @param strIn 需解密的字符串
     * @return 解密后的字符串
     * @throws Exception
     */
    public String decrypt(String strIn) throws Exception {
        return new String(decrypt(hexStr2ByteArr(strIn)));
    }

    /**
     * 从指定字符串生成密钥，密钥所需的字节数组长度为8位 不足8位时后面补0，超出8位只取前8位
     *
     * @param arrBTmp 构成该字符串的字节数组
     * @return 生成的密钥
     * @throws java.lang.Exception
     */
    private Key getKey(byte[] arrBTmp) throws Exception {
        // 创建一个空的8位字节数组（默认值为0）
        byte[] arrB = new byte[8];

        // 将原始字节数组转换为8位
        for (int i = 0; i < arrBTmp.length && i < arrB.length; i++) {
            arrB[i] = arrBTmp[i];
        }

        // 生成密钥
        Key key = new javax.crypto.spec.SecretKeySpec(arrB, "DES");

        return key;
    }

    public static String urlEncode(String str, String enc) throws Exception {
        String urlString = null;
        try {
            // 将普通字符创转换成application/x-www-from-urlencoded字符串
            urlString = URLEncoder.encode(str,enc);
            System.out.println(urlString);
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return urlString;

    }


    public static String urlDecode(String str, String enc) throws Exception {
        String keyWord = null;
        try {
            // 将application/x-www-from-urlencoded字符串转换成普通字符串
            keyWord = URLDecoder.decode(str, enc);
            System.out.println(keyWord);

        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return keyWord;

    }

    public static void main(String args[]) {
        try {
            DESPlus des = new DESPlus("etiantianim");

//                String enStr = des.encrypt("12345");
//                System.out.println(enStr);

            String deStr = "1f47b1b0b7dda0e30845f03934b314dac670ad54c69bdcdc54f2e4c8312d0ba0230e308cd00ebbcd9821328e137834856a02db7cf9e62902de07e622e68f88c02e5f65228b215c2091ef0302de5a3068cbb168e53d0d4c8e4a344566ef54183b88d98f804fc2a61d71dd2e76774516e6b6520c60dfb37f3933d44ded1a0bb47924300f1aa81ddf88883732dc46001ea257fa4bc7e4da11decbb168e53d0d4c8e4a344566ef54183b88d98f804fc2a61dc166c577eb89958aa3608d59e633f7d4c7e2d56d0863bdb277a1fca1c6ee68208ee63d1d40e0caaba3ab3b36ac1327a5b434d3a4e3bdbf22aca56b9ca3a2d67d8d209512822213565909d949241da7b7526c57ee19319cf633d44ded1a0bb47924300f1aa81ddf88eef3c4328a4e573e2cb4dcf54b8f8492d2daabf35db8b352d65860fda05a7081fe58d865c8f3bdd4b47ec3d2093a993854179d6c720f90b4765a16a282f3e89a5659904fa845dce563556768ede6c62c798668aea00504e81ce1a8f9db87be575ada45ee221401474ad5663392b30b290651f4b8ddb8dae8b2a70455aef70dd126bceb30cc50f73b886f34d4c62b2dcb93b3445df128fa8ba53c8441390a3c11f38b9992becd4f520e5d3e595f206ec588d72b0e718133dde114d13c466ed8f6353450fffdd9ef0d3968a9ea2a4a75d7c7e2d56d0863bdb2f366eb2ace1f2aab337640695dc29d44acf03ac5e6687089528f2319e21c3d80c2a3df79ea0e57a6d2daabf35db8b35263d07429016cc5802663e239bcd1f65f384a7802c3ccd750528f2319e21c3d807c8ecac5bbfcd3dae251e7a8a53d5d8425b3c4904d05bd6b33eca9dc782c8b5188d72b0e718133dd442ff6d0bbcd8aee4267f4ed987dc380560b97568bcd57eb5251bccdc34e0e395afbbaed622b1d3c54179d6c720f90b42ff847a5cb6bee78f581dd8f9808ddaf13c8180ff9b11619d2daabf35db8b352f71873b148c9a244fe58d865c8f3bdd4667c4fdaac98805bae0b4c2f9498200c528f2319e21c3d8025d0a83ba6a48636b13f9867038b66016c3683856ecc4a87140bf845e0975225ae39a35bb197cfd183f9ea33f525e803cf17aa725851d2304c2249238c814e8b528f2319e21c3d8025d0a83ba6a4863660401794b3dc1d1aa5756ba425237b569edd6cd6b868d19c70a9eee959895f80dd4e9bd22554f5da4608d9272edc3047549f1091ea34680ab62e94a5064cef60e5d4f8361466dd71f3159a550b46c31f16e6f4e62cf00daec4f1e519eb5bb05a67d38ec9650ef7f7c5aab64e89845ae116b9c1cdc2d7315763eed7a868d6358133d44ded1a0bb47924300f1aa81ddf8876282b011a2ef111633cf7414bd00fd8c4f1e519eb5bb05a41336ef14a1661029c5083d9bd84f99c679a16b6b07b59c7f2e8d409dc4a623d248e064719315b2f5d38bfa1f71e823b0e5d3e595f206ec502ec47b93f771bd21f04971b42dcf43c0d91d3a241fbbc9de9edbd4fb02ebc09bf4994bc203ed6d588d98f804fc2a61d4eab69e9a0215e719db4768c79471608e1275958023bfd5c7b7e6c831cafa9faabaa9d6709130a95af7be7f75df1c4adfba366d1bde5be96fa63253c68a20ef9de07e622e68f88c081828afee2640e9e528bed86b700addff23dea022df6dbdeba2dfa5ed21dff5c8adc1195d0045b6da5e449e86496684da68d6de3d50f17b0af98899a1a90c90d528f2319e21c3d8076d81466ed26f525066d96fcda4ab35fee7fc0b1f335b3ab54179d6c720f90b42ff847a5cb6bee78f581dd8f9808ddafeace7cba1e8d2023d2daabf35db8b3528b0cc4ca7118f586ceb08b21f126e8b1fe58d865c8f3bdd4dac5b1141a72f34554179d6c720f90b4eff9be29df2f61ee8164fd3569deb1036be2d7c834106b45cf95e89e535a58d933eca9dc782c8b517d13758c13289f8e3323e5d2182db6736a1e52204dd3ceb02b3fb8bf3a9dc16c5789b85567d0a35788d98f804fc2a61d72506aa4e222ad2bb66f499f07b8cab5c2997b97a0dcfdad8ab25d9b0a9a9c1585dced5b4db46ef7c0fc3c599edd69e323a9eaae08e2ca94ebede0c61dd4cdfa88625ef0c95a583a7d18acb4cad1215caf0b3b4f9d6c60971fff5dbe64c94ba93c6375f25be77d82c6565d297ab8b0d340cbc9136e341d843fee986c70ca5787514db4faf51ef8ec810cb09bf1fbfee615f7e505e2cf32e49b3888ee06cbd3dda45966c4278b6aabdf71669fd4a7a4e1c2cc4be8a83b6b8d";
            String deStr1 = des.decrypt(deStr);
            System.out.println(deStr1);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            String urlDecode = urlDecode(deStr1,"UTF-8");
            System.out.println(urlDecode);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
