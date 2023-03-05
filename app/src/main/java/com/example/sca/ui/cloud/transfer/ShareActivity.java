package com.example.sca.ui.cloud.transfer;

import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_IMAGE_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_REGION;

import android.annotation.SuppressLint;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.TextUtils;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.Share.MySqliteOpenHelper;
import com.example.sca.ui.cloud.CosServiceFactory;
import com.example.sca.ui.cloud.CosUserInformation;
import com.example.sca.ui.cloud.common.base.BaseActivity;
import com.example.sca.ui.cloud.encryptalgorithm.AESUtils;
import com.example.sca.ui.cloud.encryptalgorithm.HexStringAndByte;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeDecryptionException;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeEncrypted;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeEncryptionException;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbePublicKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeSecretMasterKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.Cpabe;
import com.tencent.cos.xml.CosXmlService;
import com.tencent.cos.xml.exception.CosXmlClientException;
import com.tencent.cos.xml.exception.CosXmlServiceException;
import com.tencent.cos.xml.listener.CosXmlResultListener;
import com.tencent.cos.xml.model.CosXmlRequest;
import com.tencent.cos.xml.model.CosXmlResult;
import com.tencent.cos.xml.model.PresignedUrlRequest;
import com.tencent.cos.xml.transfer.COSXMLDownloadTask;
import com.tencent.cos.xml.transfer.COSXMLUploadTask;
import com.tencent.cos.xml.transfer.TransferConfig;
import com.tencent.cos.xml.transfer.TransferManager;
import com.tencent.cos.xml.transfer.TransferState;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ShareActivity extends BaseActivity {
    private static final String TAG = "ShareActivity";

    private static final String AES_SHARE_KEY = "MYSharePassWords";

    private TextView tv_share;

    public final static String ACTIVITY_SHARE_STRATEGY = "share_strategy";


    private String bucketName;
    private String bucketRegion;
    private String sourcecosPath;
    private String savepath;
    private String attributes;
    private CosUserInformation cosUserInformation;
    private AbeSecretMasterKey smKey;
    private AESUtils aesUtils;

    private String app_id;

    /*
     * {@link CosXmlService} 是您访问 COS 服务的核心类，它封装了所有 COS 服务的基础 API 方法。
     * <p>
     * 每一个{@link CosXmlService} 对象只能对应一个 region，如果您需要同时操作多个 region 的
     * Bucket，请初始化多个 {@link CosXmlService} 对象。
     */
    private CosXmlService cosXmlService;

    /*
     * {@link TransferManager} 进一步封装了 {@link CosXmlService} 的上传和下载接口，当您需要
     * 上传文件到 COS 或者从 COS 下载文件时，请优先使用这个类。
     */
    private TransferManager transferManager;
    private COSXMLUploadTask cosxmlTask;
    private COSXMLDownloadTask cosxmlTask2;


    @SuppressLint("Range")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_share);
        tv_share = findViewById(R.id.tv_share);


        bucketName = getIntent().getStringExtra(ACTIVITY_EXTRA_BUCKET_NAME);
        bucketRegion = getIntent().getStringExtra(ACTIVITY_EXTRA_REGION);
        sourcecosPath = getIntent().getStringExtra(ACTIVITY_EXTRA_IMAGE_NAME);
        attributes = getIntent().getStringExtra(ACTIVITY_SHARE_STRATEGY);


        app_id = Config.COS_APP_ID;
        cosUserInformation = new CosUserInformation(Config.COS_SECRET_ID,Config.COS_SECRET_KEY, app_id);


        if (cosUserInformation.getCOS_SECRET_ID().length() == 0 || cosUserInformation.getCOS_SECRET_KEY().length() == 0) {
            finish();
        }

        cosXmlService = CosServiceFactory.getCosXmlService(this, bucketRegion,
                cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), true);
        TransferConfig transferConfig = new TransferConfig.Builder().build();
        transferManager = new TransferManager(cosXmlService, transferConfig);

        aesUtils = new AESUtils();



        //查询数据库获取主密钥
        String masterKey = "";
        SQLiteOpenHelper helper = MySqliteOpenHelper.getInstance(this);
        SQLiteDatabase readableDatabase = helper.getReadableDatabase();
        if (readableDatabase.isOpen()) {
            Cursor cursor = readableDatabase.rawQuery("select * from masters where nameID=" + app_id, null);
            cursor.moveToFirst();
            masterKey = cursor.getString(cursor.getColumnIndex("masterKey"));
            cursor.close();
            readableDatabase.close();
        }
        try {
            smKey = AbeSecretMasterKey.readFromByteArray(HexStringAndByte.hexStringToByte(masterKey));
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (smKey != null) {
            //图像下载并解密到本地的路径
            download(sourcecosPath);
        } else
            Toast.makeText(this, "请先分享密钥给接收方", Toast.LENGTH_LONG).show();
    }


    private void download(String path) {
        String filename = getFileNameWithSuffix(path);
        if (cosxmlTask2 == null) {
            String downloadPath = Environment.getExternalStorageDirectory()
                    + File.separator + Environment.DIRECTORY_DCIM
                    + File.separator + "cosdownload" + File.separator;
            cosxmlTask2 = transferManager.download(this, bucketName, path,
                    downloadPath, "cos_download_" + filename);

            cosxmlTask2.setCosXmlResultListener(new CosXmlResultListener() {
                @SuppressLint("SetTextI18n")
                @Override
                public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                    cosxmlTask2 = null;
                    toastMessage("下载图像到本地成功");
                    // 将加密原图解密并保存
                    try {
                        savepath =  aesUtils.decryptCTRFile(downloadPath + "cos_download_" + filename,filename,getApplicationContext());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    if (savepath != null) {
                        deleteImage(downloadPath + "cos_download_" + filename);// 删除未解密图片
                    }
                    Log.e(TAG, "图像下载并解密到本地的路径: " + savepath);
                    upload(savepath); // 获取到图像后用分享专用密钥加密后上传
                }

                @Override
                public void onFail(CosXmlRequest request, CosXmlClientException exception, CosXmlServiceException serviceException) {
                    if (cosxmlTask2.getTaskState() != TransferState.PAUSED) {
                        cosxmlTask2 = null;
                        toastMessage("下载图像到本地失败");
                    }
                    if (exception != null) {
                        exception.printStackTrace();
                    }
                    if (serviceException != null) {
                        serviceException.printStackTrace();
                    }
                }
            });

        }
    }

    private void upload(String path) {

        if (TextUtils.isEmpty(path)) {
            toastMessage("请先选择文件");
            return;
        }

        if (cosxmlTask == null) {

            String filename = getFileNameWithSuffix(path);
            // AES 加密图片
            String encryptimagepath = aesUtils.encryptCTRFileShare(path, filename, AES_SHARE_KEY);

            File file = new File(encryptimagepath);
            String cosPath = "picture" + File.separator + "sharegallery" + File.separator + file.getName();  //存储桶中的分享文件夹路径
            // 上传文件到指定分享文件夹
            cosxmlTask = transferManager.upload(bucketName, cosPath, encryptimagepath, null);

            //设置返回结果回调
            cosxmlTask.setCosXmlResultListener(new CosXmlResultListener() {
                @Override
                public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                    COSXMLUploadTask.COSXMLUploadTaskResult cOSXMLUploadTaskResult = (COSXMLUploadTask.COSXMLUploadTaskResult) result;

                    cosxmlTask = null;
                    setResult(RESULT_OK);
                    try {
                        //需分享加密AES密钥。
                        String shareurl = getPresignDownloadUrl(bucketName, cosPath); // 获取带签名的要分享的图片url
                        Log.e(TAG, "shareurl: " + shareurl);
                        AbePublicKey pubKey = smKey.getPublicKey();
                        Log.e(TAG, "encryptByte: " + Arrays.toString(AES_SHARE_KEY.getBytes(StandardCharsets.UTF_8)));
                        AbeEncrypted ct1 = Cpabe.encrypt(pubKey, attributes, AES_SHARE_KEY.getBytes(StandardCharsets.UTF_8)); //加密密钥后生成的密文
                        byte[] enKeyBytes = ct1.writeEncryptedData(pubKey);

                        String url = shareurl + "&" + HexStringAndByte.printHexString(enKeyBytes) + "&" + app_id;
                        Log.e(TAG, "url: " + url);

                        //
                        uiAction(new Runnable() {
                            @Override
                            public void run() {
                                tv_share.setText(url);
                            }
                        });
                    } catch (CosXmlClientException | AbeEncryptionException | IOException | AbeDecryptionException e) {
                        e.printStackTrace();
                    }
                    Log.e(TAG, "ShareSuccess: ");
                    toastMessage("分享图片生成成功");

                    //删除原图片与加密图片
                    deleteImage(path);
                    deleteImage(encryptimagepath);
                }

                @Override
                public void onFail(CosXmlRequest request, CosXmlClientException exception, CosXmlServiceException serviceException) {
                    if (cosxmlTask.getTaskState() != TransferState.PAUSED) {
                        cosxmlTask = null;
                        uiAction(new Runnable() {
                            @Override
                            public void run() {
                                tv_share.setText("无");
                            }
                        });
                        Log.e(TAG, "onFail: ");

                    }
                    if (exception != null) {
                        exception.printStackTrace();
                    }
                    if (serviceException != null) {
                        serviceException.printStackTrace();
                    }
                }
            });

        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (cosXmlService != null) {
            cosXmlService.release();
        }
    }


    /**
     * 获取文件名及后缀
     */
    public String getFileNameWithSuffix(String path) {
        if (TextUtils.isEmpty(path)) {
            return "";
        }
        int start = path.lastIndexOf("/");
        if (start != -1) {
            return path.substring(start + 1);
        } else {
            return "";
        }
    }

    protected void uiAction(Runnable runnable) {
        findViewById(android.R.id.content).post(runnable);
    }


    /**
     * 获取预签名访问链接
     */
    private String getPresignDownloadUrl(String bucketName, String cospath) throws CosXmlClientException {

        String method = "GET"; //请求 HTTP 方法.
        PresignedUrlRequest presignedUrlRequest = new PresignedUrlRequest(bucketName
                , cospath);
        presignedUrlRequest.setRequestMethod(method);

        // 设置签名有效期为 60s，注意这里是签名有效期，您需要自行保证密钥有效期
        presignedUrlRequest.setSignKeyTime(3600);
        // 设置不签名 Host
        presignedUrlRequest.addNoSignHeader("Host");

        return cosXmlService.getPresignedURL(presignedUrlRequest);


    }


    public void deleteImage(String path) {
        File file = new File(path);
        //删除系统缩略图
        getContentResolver().delete(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, MediaStore.Images.Media.DATA + "=?", new String[]{path});
        //删除手机中图片
        boolean delete = file.delete();

    }


}