package com.example.sca.ui.cloud.encryptalgorithm;

import android.content.Context;

import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class KeyEncryptedUtil{

    // tuning parameters
    // these sizes are relatively arbitrary
    private static final int seedBytes = 20;
    private static final int hashBytes = 16; // AES加密密钥要求16位

    // increase iterations as high as your performance can tolerate
    // since this increases computational cost of password guessing
    // which should help security
    private static final int iterations = 1000;



    public static byte[] keysalt(String key, Context context) { // 输入密钥 生成加盐密钥

        byte[] salt = getsalt(context);

        PKCS5S2ParametersGenerator kdf = new PKCS5S2ParametersGenerator();

        kdf.init(key.getBytes(StandardCharsets.UTF_8), salt, iterations);

        byte[] hash = ((KeyParameter) kdf.generateDerivedMacParameters(8*hashBytes)).getKey();

        return hash;
    }

    // 获取 salt 值 没有则新建一个
    private static byte[] getsalt(Context context) {
        byte[] salt = null;
        File file = new File(context.getFilesDir(), "salt.txt");
        try{
            if(!file.exists()) {
                file.createNewFile();
                SecureRandom rng = new SecureRandom();
                byte[] salt1 = rng.generateSeed(seedBytes);
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(salt1);
                fos.close();
            }
            else {
                int length = (int) file.length();
                byte[] salt2 = new byte[length];
                FileInputStream in = new FileInputStream(file);
                in.read(salt2);
                in.close();
            }

        }catch(Exception e){
            e.printStackTrace();
        }
        return salt;

    }


}
