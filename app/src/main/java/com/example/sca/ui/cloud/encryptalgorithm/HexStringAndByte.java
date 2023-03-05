package com.example.sca.ui.cloud.encryptalgorithm;

public class HexStringAndByte {
    /**
     * 把16进制字符串转换成字节数组
     * @param hex String
     * @return byte[]
     */
    public static byte[] hexStringToByte(String hex) {
        if ((hex == null) || (hex.equals(""))){
            return null;
        }
        else if (hex.length()%2 != 0){
            return null;
        }
        else{
            hex = hex.toUpperCase();
            int len = hex.length()/2;
            byte[] bytes = new byte[len];
            char[] hc = hex.toCharArray();
            for (int i=0; i<len; i++){
                int p=2*i;
                bytes[i] = (byte) (charToByte(hc[p]) << 4 | charToByte(hc[p+1]));
            }
            return bytes;
        }

    }

    private static int charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    /**
     * 字节数组转换成16进制字符
     * @param  bytes
     * @return str
     */
    public static  String printHexString(byte[] bytes) {
        StringBuilder str = new StringBuilder();
        int size=bytes.length;
        for (byte value : bytes) {
            String hex = Integer.toHexString(value & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            str.append(hex.toUpperCase());
        }
        return str.toString();
    }


}
