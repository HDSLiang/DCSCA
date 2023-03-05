package com.example.sca.ui.Share;

import android.annotation.SuppressLint;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.example.sca.R;
import com.example.sca.ui.cloud.common.base.BaseActivity;
import com.example.sca.ui.cloud.encryptalgorithm.AESUtils;
import com.example.sca.ui.cloud.encryptalgorithm.HexStringAndByte;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeDecryptionException;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeEncrypted;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbePrivateKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbePublicKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeSecretMasterKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.Cpabe;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ReceiveActivity extends BaseActivity {
    private static final String TAG = "ReceiveActivity";
    AESUtils aesUtils = new AESUtils();
    private ImageView imageView; //显示分享图片
    private TextView textView;  // 图片名
    private String shareUrl;   // 发送方图片URL
    private String enShareKey; // 加密分享密钥
    private String nameId;  // 发送方ID
    private Bitmap bitmap;
    private String priKey;




    public final static String ACTIVITY_EXTRA_SHARE_URL = "share_url";


    @SuppressLint("Range")
    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_receive);

        imageView = findViewById(R.id.share_image_display);
        textView = findViewById(R.id.share_image_name);
        textView.setText("请等待图片加载中");


        // shareURl应加密钥再加身份（shareactivity里写） 可用 COS_APP_ID做身份识别
        // receive这边要写个接收功能 ： 1.shareurl 拆分 确认身份    2.数据库读取私钥 数据库格式:  COSAPP_ID  私钥   3.私钥解密获取AESkey 4.AESkey  aesDecryptShare 解密
        // 密钥接收可加限制 十六进制字符串  URl接收 格式为URL  --设置 Edittext 限制输入格式

        String url = getIntent().getStringExtra(ACTIVITY_EXTRA_SHARE_URL); // shareurl & ensharekey &A PPID
        Log.e(TAG, "url: " + url);

        nameId = url.substring(url.lastIndexOf("&") + 1);
        Log.e(TAG, "appId: " + nameId);

        String subUrl = url.substring(0, url.lastIndexOf("&"));
        Log.e(TAG, "subUrl: " + subUrl);

        shareUrl = subUrl.substring(0, subUrl.lastIndexOf("&"));
        Log.e(TAG, "shareUrl: " + shareUrl);

        enShareKey = subUrl.substring(subUrl.lastIndexOf("&") + 1);
        Log.e(TAG, "enShareKey: " + enShareKey);

        String filename = shareUrl.substring(shareUrl.lastIndexOf("/") + 1, shareUrl.lastIndexOf("?"));
        //从URL中获取文件名
        Log.e(TAG, "filename: " + filename);


        SQLiteOpenHelper helper = MySqliteOpenHelper.getInstance(this);
        SQLiteDatabase readableDatabase = helper.getReadableDatabase();
        if (readableDatabase.isOpen()) {
            Cursor cursor = readableDatabase.rawQuery("select * from persons where nameID=" + nameId, null);
            if (cursor != null) {
                cursor.moveToFirst();
                priKey = cursor.getString(cursor.getColumnIndex("privateKey"));
                Log.e(TAG, "priKey数据库: " + priKey);
                Log.e(TAG, "priKey数据库长度: " + priKey.length());
                cursor.close();
            } else
                Toast.makeText(this, "无解锁密钥，请先发送密钥", Toast.LENGTH_SHORT).show();
            readableDatabase.close();
        }


        byte[] decryptByte = null;
        try {
            AbeSecretMasterKey smKey = Cpabe.setup();
            AbePublicKey pubKey = smKey.getPublicKey();
            AbeEncrypted ct = AbeEncrypted.read(HexStringAndByte.hexStringToByte(enShareKey), pubKey);
            byte[] priKeyBytes = HexStringAndByte.hexStringToByte(priKey);
            AbePrivateKey abePrivateKey = AbePrivateKey.readFromByteArray(priKeyBytes);
            decryptByte = Cpabe.decrypt(abePrivateKey, ct);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (AbeDecryptionException e) {
            textView.setText("您不符合解密条件");
            e.printStackTrace();
        }

        Log.e(TAG, "decryptByte: " + Arrays.toString(decryptByte));
        if(decryptByte!= null) {
            String deckey = new String(decryptByte, StandardCharsets.UTF_8);
            Log.e(TAG, "deckey: " + deckey);


            String savepath = Environment.getExternalStorageDirectory()
                    + File.separator + Environment.DIRECTORY_DCIM
                    + File.separator + "cosShare" + File.separator;

            // 检测系统相册目录是否存在，不存在就创建
            File galleryPath = new File(savepath);
            if (!galleryPath.exists()) {
                galleryPath.mkdirs();
            }

            String localpath = savepath + filename;


            new Thread(new Runnable() {
                @Override
                public void run() {

                    try {
                        getImg(shareUrl, localpath, ReceiveActivity.this);
                        bitmap = aesUtils.decryptCTRFileShare(localpath, deckey);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (new File(localpath).exists()) {
                                imageView.setImageBitmap(bitmap);
                                textView.setText(filename);

//            String s = saveDecryptImageToGallery(ReceiveActivity.this, bitmap, filename);
//            Log.e(TAG, "解密路径: " + s);
                            } else
                                toastMessage("请检查分享链接");
                        }
                    });

                }

            }).start();
        }




    }

    /**
     * @param @param  url 图片的连接地址
     * @param @throws IOException
     * @return
     * @throws
     * @Title: getImg
     * @Description: 通过一个url 去获取图片
     */
    public static void getImg(String url, String path, Context context) throws IOException {
        long startTime = System.currentTimeMillis();
        URL imgURL = new URL(url.trim());//转换URL
        HttpURLConnection urlConn = (HttpURLConnection) imgURL.openConnection();//构造连接
        urlConn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36");
        urlConn.connect();
        Log.e(TAG, "获取连接=" + urlConn.getResponseMessage());
        if (urlConn.getResponseCode() == 200) {//返回的状态码是200 表示成功
            InputStream ins = urlConn.getInputStream(); //获取输入流,从网站读取数据到 内存中
            OutputStream out = new BufferedOutputStream(new FileOutputStream(new File(path)));
            int len = 0;
            byte[] buff = new byte[1024 * 10];//10k缓冲流 视你内存大小而定

            while (-1 != (len = (new BufferedInputStream(ins)).read(buff))) {//长度保存到len,内容放入到 buff
                out.write(buff, 0, len);//将图片数组内容写入到图片文件
            }
            urlConn.disconnect();
            ins.close();
            out.close();
            Log.e(TAG, "获取图片完成,耗时=" + ((System.currentTimeMillis() - startTime) / 1000) + "s");
        }
    }

    /*
     * 保存解密图到图库
     *
     * @param bmp
     * @param bitName
     */
    public static String saveDecryptImageToGallery(Context context, Bitmap bmp, String bitName) {
        // 系统相册目录
        File galleryPath = new File(Environment.getExternalStorageDirectory()
                + File.separator + Environment.DIRECTORY_DCIM
                + File.separator + "cosShare" + File.separator);
        if (!galleryPath.exists()) {
            galleryPath.mkdirs();
        }

        File file = new File(galleryPath, bitName);

        try {
            FileOutputStream fos = new FileOutputStream(file);
            bmp.compress(Bitmap.CompressFormat.JPEG, 100, fos);
            fos.flush();
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return file.getAbsolutePath();

        //插入到系统图库
//        return MediaStore.Images.Media.insertImage(context.getContentResolver(), bmp, "菜单", bitName);
    }


}




