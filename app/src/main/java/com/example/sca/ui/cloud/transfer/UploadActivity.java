package com.example.sca.ui.cloud.transfer;


import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_FOLDER_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_REGION;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.ThumbnailUtils;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;

import androidx.annotation.Nullable;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.OSS;
import com.alibaba.sdk.android.oss.OSSClient;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.callback.OSSProgressCallback;
import com.alibaba.sdk.android.oss.common.auth.OSSPlainTextAKSKCredentialProvider;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectResult;
import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.cloud.CosServiceFactory;
import com.example.sca.ui.cloud.CosUserInformation;
import com.example.sca.ui.cloud.common.FilePathHelper;
import com.example.sca.ui.cloud.common.Utils;
import com.example.sca.ui.cloud.common.base.BaseActivity;
import com.example.sca.ui.cloud.encryptalgorithm.AESUtils;
import com.example.sca.ui.cloud.encryptalgorithm.FastBlur;
import com.example.sca.ui.cloud.encryptalgorithm.ImageUtil;
import com.example.sca.ui.cloud.object.ObjectActivity;
import com.tencent.cos.xml.CosXmlService;
import com.tencent.cos.xml.exception.CosXmlClientException;
import com.tencent.cos.xml.exception.CosXmlServiceException;
import com.tencent.cos.xml.listener.CosXmlProgressListener;
import com.tencent.cos.xml.listener.CosXmlResultListener;
import com.tencent.cos.xml.model.CosXmlRequest;
import com.tencent.cos.xml.model.CosXmlResult;
import com.tencent.cos.xml.transfer.COSXMLUploadTask;
import com.tencent.cos.xml.transfer.TransferConfig;
import com.tencent.cos.xml.transfer.TransferManager;
import com.tencent.cos.xml.transfer.TransferState;
import com.tencent.cos.xml.transfer.TransferStateListener;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Objects;


/*
 * Created by jordanqin on 2020/6/18.
 * 文件上传页面
 * <p>
 * Copyright (c) 2010-2020 Tencent Cloud. All rights reserved.
 */
public class UploadActivity extends BaseActivity implements View.OnClickListener {
    private final int OPEN_FILE_CODE = 10001;


    //图片文件本地显示
    private ImageView iv_image;
    //本地文件路径
    private TextView tv_name;
    //上传状态
    private TextView tv_state;
    //上传进度
    private TextView tv_progress;
    //上传进度条
    private ProgressBar pb_upload;

    //操作按钮（开始和取消）
    private Button btn_left;
    //操作按钮（暂停和恢复）
    private Button btn_right;
    private RadioGroup radgroup;

    private String bucketName;
    private String bucketRegion;
    private String folderName;
    private AESUtils aesUtils;
    private CosUserInformation cosUserInformation;


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

    // OSS类
    private OSSPlainTextAKSKCredentialProvider credentialProvider;
    private OSS ossClient;
    /*
     * 上传时的本地和 COS 路径
     */
    private String currentUploadPath; // 图像路径

    private final String photoPrefix = "picture";
    private static final String TAG = "UploadActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.upload_activity);

        bucketName = getIntent().getStringExtra(ACTIVITY_EXTRA_BUCKET_NAME);
        bucketRegion = getIntent().getStringExtra(ACTIVITY_EXTRA_REGION);
        folderName = getIntent().getStringExtra(ACTIVITY_EXTRA_FOLDER_NAME);

        iv_image = findViewById(R.id.iv_image);
        tv_name = findViewById(R.id.tv_name);
        tv_state = findViewById(R.id.tv_state);
        tv_progress = findViewById(R.id.tv_progress);
        pb_upload = findViewById(R.id.pb_upload);
        btn_left = findViewById(R.id.btn_left);
        btn_right = findViewById(R.id.btn_right);
        radgroup = findViewById(R.id.radioGroup);

        btn_right.setOnClickListener(this);
        btn_left.setOnClickListener(this);

        cosUserInformation = new CosUserInformation(Config.COS_SECRET_ID,Config.COS_SECRET_KEY,Config.COS_APP_ID);

        credentialProvider = new OSSPlainTextAKSKCredentialProvider(Config.OSS_ACCESS_KEY_ID,Config.OSS_ACCESS_KEY_SECRET);
        ossClient = new OSSClient(this,Config.OSS_ENDPOINT,credentialProvider); // 备份云存储桶地域固定为 endpoint 中的地域

        if (cosUserInformation.getCOS_APP_ID().length() == 0 ||
                cosUserInformation.getCOS_SECRET_ID().length() == 0 ||
                cosUserInformation.getCOS_SECRET_KEY().length() == 0 ||
                credentialProvider.getAccessKeyId().length() == 0 ||
                credentialProvider.getAccessKeySecret().length() == 0) {
            finish();
        }


        cosXmlService = CosServiceFactory.getCosXmlService(this, bucketRegion,
                cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), true);
        TransferConfig transferConfig = new TransferConfig.Builder().build();
        transferManager = new TransferManager(cosXmlService, transferConfig);

        aesUtils = new AESUtils();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.upload, menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.choose_photo) {
            //为了示例简单明了 正在处理文件时不允许选择文件
            if (cosxmlTask == null) {
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.setType("image/*");
                startActivityForResult(intent, OPEN_FILE_CODE);
                return true;
            } else {
                toastMessage("当前文件未处理完毕，不能选择新文件");
            }
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btn_left) {
            if ("开始".contentEquals(btn_left.getText())) {

                // 存在问题 第二次就无法跳转了
                Intent intent2 = new Intent(this, ObjectActivity.class);
                intent2.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
                startActivity(intent2);

                cosUpload();
                uploadThumbnailMode();

            } else {//取消
                if (cosxmlTask != null) {
                    // 取消上传
                    cosxmlTask.cancel();
                    finish();
                } else {
                    toastMessage("操作失败");
                }
            }
        } else if (v.getId() == R.id.btn_right) {
            if ("暂停".contentEquals(btn_right.getText())) {
                if (cosxmlTask != null && cosxmlTask.getTaskState() == TransferState.IN_PROGRESS) {
                    // 暂停上传
                    cosxmlTask.pause();
                    btn_right.setText("恢复");
                } else {
                    toastMessage("操作失败");
                }
            } else {//恢复
                if (cosxmlTask != null && cosxmlTask.getTaskState() == TransferState.PAUSED) {
                    // 如果暂停成功，可以恢复上传
                    cosxmlTask.resume();
                    btn_right.setText("暂停");
                } else {
                    toastMessage("操作失败");
                }
            }
        }
    }



    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == OPEN_FILE_CODE && resultCode == Activity.RESULT_OK && data != null) {
            String path = FilePathHelper.getAbsPathFromUri(this, data.getData());
            if (TextUtils.isEmpty(path)) {
                iv_image.setImageBitmap(null);
                tv_name.setText("");
            } else {
                //直接用选择的文件URI去展示图片
                //如果所选文件不是图片文件，则展示文件图标
                try {
                    Bitmap bitmap = BitmapFactory.decodeFile(path);
                    iv_image.setImageBitmap(bitmap);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (path != null)
                    tv_name.setText(getFileNameWithSuffix(path));
                else
                    tv_name.setText(null);
            }

            currentUploadPath = path;


            pb_upload.setProgress(0);
            tv_progress.setText("");
            tv_state.setText("无");
        }
    }

    /**
     * 刷新上传状态
     *
     * @param state 状态 {@link TransferState}
     */
    private void refreshUploadState(final TransferState state) {
        uiAction(new Runnable() {
            @Override
            public void run() {
                tv_state.setText(state.toString());
            }
        });

    }

    /**
     * 刷新上传进度
     *
     * @param progress 已上传文件大小
     * @param total    文件总大小
     */
    private void refreshUploadProgress(final long progress, final long total) {
        uiAction(new Runnable() {
            @SuppressLint("SetTextI18n")
            @Override
            public void run() {
                pb_upload.setProgress((int) (100 * progress / total));
                tv_progress.setText(Utils.readableStorageSize(progress) + "/" + Utils.readableStorageSize(total));
            }
        });
    }

    private void cosUpload(){

        if (TextUtils.isEmpty(currentUploadPath)) {
            toastMessage("请先选择文件");
            return;
        }

        if (cosxmlTask == null) {
            //从当前路径获取原图像文件名
            String filename = getFileNameWithSuffix(currentUploadPath);

            // AES 加密原图片
            String encryptimagepath = aesUtils.encryptCTRFile(currentUploadPath, filename,this);


            File file = new File(encryptimagepath);
            String cosPath;

            if (TextUtils.isEmpty(folderName)) {
                cosPath = photoPrefix + File.separator + file.getName();
            } else {
                cosPath = folderName + File.separator + file.getName();
            }
            // 上传文件
            cosxmlTask = transferManager.upload(bucketName, cosPath, encryptimagepath, null);

            // 状态检测
            cosxmlTask.setTransferStateListener(new TransferStateListener() {
                @Override
                public void onStateChanged(final TransferState state) {
                    refreshUploadState(state);
                }
            });

            //设置上传进度回调
            cosxmlTask.setCosXmlProgressListener(new CosXmlProgressListener() {
                @Override
                public void onProgress(final long complete, final long target) {
                    refreshUploadProgress(complete, target);
                }
            });

            //设置返回结果回调
            cosxmlTask.setCosXmlResultListener(new CosXmlResultListener() {
                @Override
                public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                    COSXMLUploadTask.COSXMLUploadTaskResult cOSXMLUploadTaskResult = (COSXMLUploadTask.COSXMLUploadTaskResult) result;
                    cosxmlTask = null;
                    toastMessage("主云上传成功");

                    ossUpload(cosPath,encryptimagepath); // 备份云上传

                }

                @Override
                public void onFail(CosXmlRequest request, CosXmlClientException exception, CosXmlServiceException serviceException) {
                    toastMessage("主云上传失败");
                    if (cosxmlTask.getTaskState() != TransferState.PAUSED) {
                        cosxmlTask = null;
                        uiAction(new Runnable() {
                            @Override
                            public void run() {
                                pb_upload.setProgress(0);
                                tv_progress.setText("");
                                tv_state.setText("无");
                            }
                        });
                    }
                    if (exception != null) {
                        exception.printStackTrace();
                    }
                    if (serviceException != null) {
//                        serviceException.printStackTrace();
                        // 服务异常。
                        Log.e("ErrorCode", serviceException.getErrorCode());
                        Log.e("RequestId", serviceException.getRequestId());
                        Log.e("HttpMessage", serviceException.getHttpMessage());
                        Log.e("Message", serviceException.getMessage());
                    }
                }
            });
            btn_left.setText("取消");
        }
    }

    //检测缩略图生成方式
    private void uploadThumbnailMode()
    {
        for (int i = 0; i < radgroup.getChildCount(); i++) {
            RadioButton rd = (RadioButton) radgroup.getChildAt(i);

            if (rd.isChecked()) {
                //生成当前要上传原照片的缩略图
                //            //用做水印的图片过大可适当调节
                Bitmap bitmap = BitmapFactory.decodeFile(currentUploadPath);
                Bitmap suoxiao = ThumbnailUtils.extractThumbnail(bitmap,400,400);
                String filename = getFileNameWithSuffix(currentUploadPath);
                switch (i){
                    case 0: // 保存缩略图并加密后删除未加密缩略图，
                        String thumbnailPath = saveBitmapToGallery(this, suoxiao, filename);
                        Log.e(TAG, "加密前缩略图路径: " + thumbnailPath);
                        String thbfilename = getFileNameWithSuffix(thumbnailPath);  // 获取缩略图文件名
//                        String thumbnailUploadPath= aesUtils.aesEncrypt(thumbnailPath, thbfilename);

                        String thumbnailUploadPath= aesUtils.encryptCTRFile(thumbnailPath, thbfilename,this);

                        Log.e(TAG, "最终上传缩略图: "+ thumbnailUploadPath );
                        uploadthumbnail(thumbnailUploadPath);
                        //删除原缩略图
                        deleteImage(thumbnailPath);
                        break;

                    case 1: //直接高斯模糊后保存
                        Bitmap doBlurBitmap = doBlur(suoxiao);
                        String doBlurthbPath = saveBitmapToGallery(this, doBlurBitmap, filename);
                        Log.e(TAG, "最终上传缩略图: "+ doBlurthbPath );
                        uploadthumbnail(doBlurthbPath);
                        break;

                    case 2://直接添加水印后保存
                        Bitmap waterMaskBitmap = waterMaskVideoPhoto(suoxiao);
                        String waterMaskthbPath = saveBitmapToGallery(this, waterMaskBitmap, filename);
                        Log.e(TAG, "最终上传缩略图: "+ waterMaskthbPath );
                        uploadthumbnail(waterMaskthbPath);
                        break;

                    case 3://直接灰度提取后保存
                        Bitmap greyBitmap = ImageUtil.bitmap2Gray(suoxiao);
                        String greythbPath = saveBitmapToGallery(this, greyBitmap, filename);
                        Log.e(TAG, "最终上传缩略图: "+ greythbPath );
                        uploadthumbnail(greythbPath);
                        break;
                }
                break;
            }
        }
    }

    private void uploadthumbnail(String path) {

        if (TextUtils.isEmpty(path)) {
            Log.e(TAG, "uploadthumbnail: 路径为空" );
            return;
        }

        if (cosxmlTask != null) {

            File file = new File(path);
            String cosPaththb = photoPrefix + File.separator + "thumbnail" + File.separator + file.getName();

            // 上传文件
            cosxmlTask = transferManager.upload(bucketName, cosPaththb,
                    path, null);

            // 状态检测
            cosxmlTask.setTransferStateListener(new TransferStateListener() {
                @Override
                public void onStateChanged(final TransferState state) {
                    refreshUploadState(state);
                }
            });

            //设置上传进度回调
            cosxmlTask.setCosXmlProgressListener(new CosXmlProgressListener() {
                @Override
                public void onProgress(long complete, long target) {
                    // todo Do something to update progress...
                }
            });
            //设置返回结果回调
            cosxmlTask.setCosXmlResultListener(new CosXmlResultListener() {
                @Override
                public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                    COSXMLUploadTask.COSXMLUploadTaskResult uploadResult =
                            (COSXMLUploadTask.COSXMLUploadTaskResult) result;
                    Log.e(TAG, "onSuccess:缩略图上传成功 ");
                    //上传完成后删除缩略图
                    deleteImage(path);

                }

                // 如果您使用 kotlin 语言来调用，请注意回调方法中的异常是可空的，否则不会回调 onFail 方法，即：
                // clientException 的类型为 CosXmlClientException?，serviceException 的类型为 CosXmlServiceException?
                @Override
                public void onFail(CosXmlRequest request,
                                   @Nullable CosXmlClientException clientException,
                                   @Nullable CosXmlServiceException serviceException) {
                    if (clientException != null) {
                        clientException.printStackTrace();
                    } else {
                        Objects.requireNonNull(serviceException).printStackTrace();
                    }
                    Log.e(TAG, "onFail: 缩略图上传失败" );

                }
            });
            //设置任务状态回调, 可以查看任务过程
            cosxmlTask.setTransferStateListener(new TransferStateListener() {
                @Override
                public void onStateChanged(TransferState state) {
                    // todo notify transfer state
                }
            });

        }
    }

    private void ossUpload(String ossPath, String encryptimagepath) {

        PutObjectRequest put = new PutObjectRequest(bucketName,ossPath,encryptimagepath);
        // 异步上传时可以设置进度回调。
        put.setProgressCallback(new OSSProgressCallback<PutObjectRequest>() {
            @Override
            public void onProgress(PutObjectRequest request, long currentSize, long totalSize) {
                Log.d("OSSPutObject", "currentSize: " + currentSize + " totalSize: " + totalSize);
            }
        });

        OSSAsyncTask task = ossClient.asyncPutObject(put, new OSSCompletedCallback<PutObjectRequest, PutObjectResult>() {
            @Override
            public void onSuccess(PutObjectRequest request, PutObjectResult result) {
                toastMessage("备份云上传成功");
                setResult(RESULT_OK);
                uiAction(new Runnable() {
                    @Override
                    public void run() {
                        btn_left.setVisibility(View.GONE);
                        btn_right.setVisibility(View.GONE);
                    }
                });
                //删除加密图片
                deleteImage(encryptimagepath);
            }

            @Override
            public void onFailure(PutObjectRequest request, ClientException clientExcepion, ServiceException serviceException) {
                toastMessage("备份云上传失败");
                // 请求异常。
                if (clientExcepion != null) {
                    // 客户端异常，例如网络异常等。
                    clientExcepion.printStackTrace();
                }
                if (serviceException != null) {
                    // 服务端异常。
                    Log.e("ErrorCode", serviceException.getErrorCode());
                    Log.e("RequestId", serviceException.getRequestId());
                    Log.e("HostId", serviceException.getHostId());
                    Log.e("RawMessage", serviceException.getRawMessage());
                }
            }
        });


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
        if(TextUtils.isEmpty(path)){
            return "";
        }
        int start = path.lastIndexOf("/");
        if (start != -1 ) {
            return path.substring(start + 1);
        } else {
            return "";
        }
    }
    protected void uiAction(Runnable runnable){
        findViewById(android.R.id.content).post(runnable);
    }


    /*
     * 保存缩略图到图库
     *
     * @param bmp
     * @param bitName
     */
    public static String saveBitmapToGallery(Context context, Bitmap bmp, String bitName) {
        // 系统相册目录
        File galleryPath = new File(Environment.getExternalStorageDirectory()
                + File.separator + Environment.DIRECTORY_DCIM
                + File.separator + "thumbnail" + File.separator);
        if (!galleryPath.exists()) {
            galleryPath.mkdirs();
        }

        String fileName ="thumbnail_" + bitName;
        File file = new File(galleryPath, fileName);

        try {
            FileOutputStream fos = new FileOutputStream(file);
            bmp.compress(Bitmap.CompressFormat.JPEG, 80, fos);
            fos.flush();
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        Log.e(TAG, "saveBitmapToGallery: "+ file.getAbsolutePath() );

        return file.getAbsolutePath();

    }


    public void deleteImage(String path){
        File file = new File(path);
        //删除系统缩略图
        getContentResolver().delete(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, MediaStore.Images.Media.DATA + "=?", new String[]{path});
        //删除手机中图片
        boolean delete = file.delete();

    }
    private Bitmap doBlur(Bitmap bitmap){
        int scaleRatio = 5;
        int blurRadius = 10;

        Bitmap scaledBitmap = Bitmap.createScaledBitmap(bitmap,
                bitmap.getWidth() / scaleRatio,
                bitmap.getHeight() / scaleRatio,
                false);
        return FastBlur.doBlur(scaledBitmap, blurRadius, true);
    }
    private Bitmap waterMaskVideoPhoto(Bitmap bitmap) {

        //使用Drawble目录下的图片做水印用的图
        Bitmap mask = BitmapFactory.decodeResource(getBaseContext().getResources(),R.drawable.smile);
        Log.e(TAG," mask宽度： "+mask.getWidth());
        Log.e(TAG," mask高度： "+mask.getHeight());
        bitmap = ImageUtil.createWaterMaskCenter(bitmap,mask);
        return bitmap;
    }

}
