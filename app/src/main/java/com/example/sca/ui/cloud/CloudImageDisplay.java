package com.example.sca.ui.cloud;

import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_IMAGE_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_REGION;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.ImageView;
import android.widget.TextView;

import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.cloud.common.base.BaseActivity;
import com.example.sca.ui.cloud.encryptalgorithm.AESUtils;
import com.tencent.cos.xml.CosXmlService;
import com.tencent.cos.xml.exception.CosXmlClientException;
import com.tencent.cos.xml.exception.CosXmlServiceException;
import com.tencent.cos.xml.listener.CosXmlResultListener;
import com.tencent.cos.xml.model.CosXmlRequest;
import com.tencent.cos.xml.model.CosXmlResult;
import com.tencent.cos.xml.transfer.COSXMLDownloadTask;
import com.tencent.cos.xml.transfer.TransferConfig;
import com.tencent.cos.xml.transfer.TransferManager;
import com.tencent.cos.xml.transfer.TransferState;

import java.io.File;

@SuppressLint("HandlerLeak")
public class CloudImageDisplay extends BaseActivity {

    private static final String TAG = "CloudImageDisplay";
    private ImageView iv_image_display;
    private TextView tv_image_name;

    private String bucketName;
    private String bucketRegion;
    private String image_key;
    private String filename;
    private AESUtils aesUtils;


    private CosUserInformation cosUserInformation;
    private CosXmlService cosXmlService;
    /**
     * {@link TransferManager} 进一步封装了 {@link CosXmlService} 的上传和下载接口，当您需要
     * 上传文件到 COS 或者从 COS 下载文件时，请优先使用这个类。
     */
    private TransferManager transferManager;
    private COSXMLDownloadTask cosxmlTask;


    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.cloud_image_display);

        bucketName = getIntent().getStringExtra(ACTIVITY_EXTRA_BUCKET_NAME);
        bucketRegion = getIntent().getStringExtra(ACTIVITY_EXTRA_REGION);
        image_key = getIntent().getStringExtra(ACTIVITY_EXTRA_IMAGE_NAME);


        iv_image_display = findViewById(R.id.cloud_image_display);
        tv_image_name = findViewById(R.id.cloud_image_name);

        cosUserInformation = new CosUserInformation(Config.COS_SECRET_ID,Config.COS_SECRET_KEY,Config.COS_APP_ID);

        if (cosUserInformation.getCOS_SECRET_ID().length() == 0 || cosUserInformation.getCOS_SECRET_KEY().length() == 0) {
            finish();
        }
        cosXmlService = CosServiceFactory.getCosXmlService(this, bucketRegion,
                cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), true);


        cosXmlService = CosServiceFactory.getCosXmlService(this, bucketRegion,
                cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), true);
        TransferConfig transferConfig = new TransferConfig.Builder().build();
        transferManager = new TransferManager(cosXmlService, transferConfig);

        aesUtils = new AESUtils();


        final File file = new File(image_key);
        filename = file.getName(); // 获取查看文件名
        String thumbnailpath = "picture" + File.separator + "thumbnail" + File.separator + "thumbnail_" + filename;
        Log.e(TAG, "thumbnailpath: " + thumbnailpath);
        Log.e(TAG, "filename: " + filename);
        // 本地缩略图存储路径
        String localPath = Environment.getExternalStorageDirectory() + File.separator
                + Environment.DIRECTORY_DCIM + File.separator + "thumbnail" + File.separator;
        //本地缩略图路径
        String localthbPath = localPath + "thumbnail_" + filename ;
        isFolderExists(localPath); // 判断缩略图存储路径是否存在，不存在就创建

        // 判断是否已经在本地缓存过缩略图
        File f = new File(localthbPath);
        if (f.exists()) {
            Log.e(TAG, "本地已缓存缩略图 ");
            if(isImageFile(localthbPath)){ // 是图片文件
                uiAction(new Runnable() {
                    @Override
                    public void run() {
                        iv_image_display.setImageURI(Uri.fromFile(f));
                    }
                });

            }
            else { //不是图片文件
//                Bitmap aesDecrypt = aesUtils.aesDecrypt(localthbPath);

                Bitmap aesDecrypt = aesUtils.decryptCTRFile(localthbPath,this);

                uiAction(new Runnable() {
                    @Override
                    public void run() {
                        iv_image_display.setImageBitmap(aesDecrypt);
                    }
                });
            }

        } else {
            Log.e(TAG, "本地未缓存缩略图 ");
            // 将对应缩略图下载到本地
            download(thumbnailpath);
        }

        tv_image_name.setText("文件名" + filename);

    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (cosXmlService != null) {
            cosXmlService.release();
        }
    }

    private void download(String path) {
        if (cosxmlTask == null) {
            String downloadPath = Environment.getExternalStorageDirectory()
                    + File.separator + Environment.DIRECTORY_DCIM
                    + File.separator + "thumbnail" + File.separator;
            cosxmlTask = transferManager.download(this, bucketName, path,
                    downloadPath, "thumbnail_" + filename);

            cosxmlTask.setCosXmlResultListener(new CosXmlResultListener() {
                @SuppressLint("SetTextI18n")
                @Override
                public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                    cosxmlTask = null;
                    toastMessage("仅显示缩略图，查看完整版请下载原图到本地查看");


                    if(isImageFile(downloadPath + "thumbnail_" + filename)){ // 是图片文件
                        uiAction(new Runnable() {
                            @Override
                            public void run() {
                                iv_image_display.setImageURI(Uri.fromFile(new File(downloadPath + "thumbnail_" + filename)));
                            }
                        });
                    }
                    else {//是加密文件
                        // 将加密缩略图解密
                        Bitmap decryptimage = aesUtils.decryptCTRFile(downloadPath + "thumbnail_" + filename,getApplicationContext());
                        uiAction(new Runnable() {
                            @Override
                            public void run() {
                                iv_image_display.setImageBitmap(decryptimage);
                            }
                        });
                    }

                }

                @Override
                public void onFail(CosXmlRequest request, CosXmlClientException exception, CosXmlServiceException serviceException) {
                    if (cosxmlTask.getTaskState() != TransferState.PAUSED) {
                        cosxmlTask = null;
                        toastMessage("加载缩略图失败");
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


    /**
     * 判断当前路径是否存在，不存在就创建
     *
     * @param strFolder
     * @return
     */
    public boolean isFolderExists(String strFolder) {
        File file = new File(strFolder);
        if (!file.exists()) {
            if (file.mkdirs()) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }


    //图片格式判断
    public static boolean isImageFile(String path) {
        Bitmap drawable2 = BitmapFactory.decodeFile(path);
        return drawable2 != null;
    }

}
