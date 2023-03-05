package com.example.sca.ui.cloud.encryptalgorithm;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Environment;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {

    //AES加密使用的秘钥，注意的是秘钥的长度必须是16位
    private static final String AES_KEY = "MyDifficultPassw";
    private static final String CIPHER_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM_CTR = "AES/CTR/NoPadding";
    private String outPath;
    private static final String TAG = "ImageEncrypt";


    /***the subroutine for enc a big file with CTR mode用CTR模式编码大文件的子程序
     * @note: test encryption time: read plain file from disk + encrypt + write ct to the disk 测试加密时间：从磁盘读取纯文件+加密+将ct写入磁盘
     * @param sourcePath: plain file path
     * @param filename: name of destination plain file
     * @return desPath: destination ct file path
     */
    public String encryptCTRFile(String sourcePath, String filename, Context context)  {
        // AES加密后的文件夹路径
        String Path = Environment.getExternalStorageDirectory()
                + File.separator + Environment.DIRECTORY_DCIM
                + File.separator + "encryptphoto" + File.separator;
        File enImagePath = new File(Path);
        if (!enImagePath.exists()) { // 文件夹不存在，则创建
            enImagePath.mkdir();
        }
        try {
            // AES加密后的图片文件路径
            String outPath = Path + filename;
            // 密钥加盐
            byte[] key = KeyEncryptedUtil.keysalt(AES_KEY,context);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CTR);
            SecretKey keyEncryptionKey = new SecretKeySpec(key, CIPHER_ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[128 / 8];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, ivParameterSpec);

            byte[] buffer = new byte[1024 * 1024];
            InputStream in = new FileInputStream(sourcePath);

            OutputStream out = new FileOutputStream(outPath);

            int index;
            out.write(iv);
            while ((index = in.read(buffer)) != -1) {
                byte[] enc = cipher.update(buffer, 0, index);
                out.write(enc);
            }
            byte[] enc = cipher.doFinal();
            out.write(enc);
            in.close();
            out.close();
            this.outPath = outPath;

        } catch (Exception e) {
            Log.e(TAG, "加密失败 " + e.getMessage(), e);
            e.printStackTrace();
        }
        Log.e(TAG, "outPath: " + this.outPath);
        return this.outPath;
    }



    /***the subroutine decryptCTRBigFile(): read ct file from disk + decrypt + write plain file to the disk
     * @note: used to test decryption time
     * @param encPath: path of ct file
     * @return image： dec image
     */
    public Bitmap decryptCTRFile(String encPath, Context context)  {
        Bitmap image = null;
        // 密钥加盐
        byte[] key = KeyEncryptedUtil.keysalt(AES_KEY,context);
        byte[] buffer = new byte[1024 * 1024];
        try {
            InputStream in = new FileInputStream(encPath);
            ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
            byte[] iv = new byte[128 / 8];
            in.read(iv);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CTR);
            SecretKey keyEncryptionKey = new SecretKeySpec(key, CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

            int index;
            while ((index = in.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                out.write(dec);
            }
            byte[] dec = cipher.doFinal();
            out.write(dec);
            in.close();
            out.close();
            //获取字节流显示图片
            byte[] bytes = out.toByteArray();
            image = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            Log.d(TAG, "decryptCTRFile: success");
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, "解密失败 " + e.getMessage(), e);
        }
        return image;
    }



    /***the subroutine decryptCTRBigFile(): read ct file from disk + decrypt + write plain file to the disk
     * @note: used to test decryption time
     * @param sourcePath: path of ct file
     * @param filename: name of destination plain file
     * @return desPath: destination dec plain file path
     */
    public String decryptCTRFile(String sourcePath ,String filename, Context context) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {

        String destFilePath = Environment.getExternalStorageDirectory()
                + File.separator + Environment.DIRECTORY_DCIM
                + File.separator + "cosShare" + File.separator;
        File sourceFile = new File(sourcePath);
        String desPath = destFilePath + filename; // desPath: path of destination plain file
        File destFile = new File(desPath);
        if (sourceFile.exists() || sourceFile.isFile()) {  // ?
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            // 密钥加盐
            byte[] key = KeyEncryptedUtil.keysalt(AES_KEY,context);
            byte[] buffer = new byte[1024 * 1024];
            InputStream in = new FileInputStream(sourcePath);
            OutputStream out = new FileOutputStream(desPath);
            byte[] iv = new byte[128 / 8];
            in.read(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CTR);
            SecretKey keyEncryptionKey = new SecretKeySpec(key, CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

            int index;
            while ((index = in.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                out.write(dec);
            }
            byte[] dec = cipher.doFinal();
            out.write(dec);
            in.close();
            out.close();
        }
        else {
            Log.d(TAG, "找不到源文件。 ");
        }

        return desPath;
    }


    /***the subroutine for enc a big file with CTR mode用CTR模式编码大文件的子程序
     * @note: test encryption time: read plain file from disk + encrypt + write ct to the disk 测试加密时间：从磁盘读取纯文件+加密+将ct写入磁盘
     * @param sourcePath: plain file path
     * @param filename: name of destination plain file
     * @param key: data encryption key
     * @return desPath: destination ct file path
     */
    public String encryptCTRFileShare(String sourcePath, String filename, String key)  {
        // AES加密后的文件夹路径
        String Path = Environment.getExternalStorageDirectory()
                + File.separator + Environment.DIRECTORY_DCIM
                + File.separator + "encryptphoto" + File.separator;
        File enImagePath = new File(Path);
        if (!enImagePath.exists()) { // 文件夹不存在，则创建
            enImagePath.mkdir();
        }
        try {
            // AES加密后的图片文件路径
            String outPath = Path + filename;

            byte[] keybytes = key.getBytes();
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CTR);
            SecretKey keyEncryptionKey = new SecretKeySpec(keybytes, CIPHER_ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[128 / 8];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, ivParameterSpec);

            byte[] buffer = new byte[1024 * 1024];
            InputStream in = new FileInputStream(sourcePath);

            OutputStream out = new FileOutputStream(outPath);

            int index;
            out.write(iv);
            while ((index = in.read(buffer)) != -1) {
                byte[] enc = cipher.update(buffer, 0, index);
                out.write(enc);
            }
            byte[] enc = cipher.doFinal();
            out.write(enc);
            in.close();
            out.close();
            this.outPath = outPath;

        } catch (Exception e) {
            Log.e(TAG, "共享加密失败 " + e.getMessage(), e);
            e.printStackTrace();
        }
        Log.e(TAG, "outPath: " + this.outPath);
        return this.outPath;
    }



    /***the subroutine decryptCTRBigFile(): read ct file from disk + decrypt + write plain file to the disk
     * @note: used to test decryption time
     * @param encPath: path of ct file
     * @param key: data encryption key
     * @return image： dec image
     */
    public Bitmap decryptCTRFileShare(String encPath, String key)  {
        Bitmap image = null;
        byte[] keyBytes = key.getBytes();
        byte[] buffer = new byte[1024 * 1024];
        try {
            InputStream in = new FileInputStream(encPath);
            ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
            byte[] iv = new byte[128 / 8];
            in.read(iv);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CTR);
            SecretKey keyEncryptionKey = new SecretKeySpec(keyBytes, CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

            int index;
            while ((index = in.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                out.write(dec);
            }
            byte[] dec = cipher.doFinal();
            out.write(dec);
            in.close();
            out.close();
            //获取字节流显示图片
            byte[] bytes = out.toByteArray();
            image = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            Log.d(TAG, "decryptCTRFile: success");
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, "共享解密失败 " + e.getMessage(), e);
        }
        return image;
    }


}
