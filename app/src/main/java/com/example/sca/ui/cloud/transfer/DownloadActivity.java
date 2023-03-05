package com.example.sca.ui.cloud.transfer;


import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_DOWNLOAD_KEY;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_REGION;

import android.annotation.SuppressLint;
import android.media.MediaScannerConnection;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.cloud.CosServiceFactory;
import com.example.sca.ui.cloud.CosUserInformation;
import com.example.sca.ui.cloud.common.Utils;
import com.example.sca.ui.cloud.common.base.BaseActivity;
import com.tencent.cos.xml.CosXmlService;
import com.tencent.cos.xml.exception.CosXmlClientException;
import com.tencent.cos.xml.exception.CosXmlServiceException;
import com.tencent.cos.xml.listener.CosXmlProgressListener;
import com.tencent.cos.xml.listener.CosXmlResultListener;
import com.tencent.cos.xml.model.CosXmlRequest;
import com.tencent.cos.xml.model.CosXmlResult;
import com.tencent.cos.xml.transfer.COSXMLDownloadTask;
import com.tencent.cos.xml.transfer.TransferConfig;
import com.tencent.cos.xml.transfer.TransferManager;
import com.tencent.cos.xml.transfer.TransferState;
import com.tencent.cos.xml.transfer.TransferStateListener;

import java.io.File;

/**
 * Created by jordanqin on 2020/6/18.
 * 文件下载页面
 * <p>
 * Copyright (c) 2010-2020 Tencent Cloud. All rights reserved.
 */
public class DownloadActivity extends BaseActivity implements View.OnClickListener {
    //文件名
    private TextView tv_name;
    //下载状态
    private TextView tv_state;
    //下载进度
    private TextView tv_progress;
    //文件下载路径
    private TextView tv_path;
    //下载进度条
    private ProgressBar pb_download;

    //操作按钮（开始和取消）
    private Button btn_left;
    //操作按钮（暂停和恢复）
    private Button btn_right;

    private String bucketName;
    private String bucketRegion;
    private String download_key;
    private String filename;

    private CosUserInformation cosUserInformation;
    private CosXmlService cosXmlService;

    /**
     * {@link TransferManager} 进一步封装了 {@link CosXmlService} 的上传和下载接口，当您需要
     * 上传文件到 COS 或者从 COS 下载文件时，请优先使用这个类。
     */
    private TransferManager transferManager;
    private COSXMLDownloadTask cosxmlTask;




    private final String TAG = "DownloadActivity";

    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.download_activity);

        bucketName = getIntent().getStringExtra(ACTIVITY_EXTRA_BUCKET_NAME);
        bucketRegion = getIntent().getStringExtra(ACTIVITY_EXTRA_REGION);
        download_key = getIntent().getStringExtra(ACTIVITY_EXTRA_DOWNLOAD_KEY);

        tv_name = findViewById(R.id.tv_name);
        tv_state = findViewById(R.id.tv_state);
        tv_progress = findViewById(R.id.tv_progress);
        tv_path = findViewById(R.id.tv_path);
        pb_download = findViewById(R.id.pb_download);
        btn_left = findViewById(R.id.btn_left);
        btn_right = findViewById(R.id.btn_right);

        btn_right.setOnClickListener(this);
        btn_left.setOnClickListener(this);

        final File file = new File(download_key);
        filename = file.getName();
        tv_name.setText("文件名：" + filename);

        cosUserInformation = new CosUserInformation(Config.COS_SECRET_ID,Config.COS_SECRET_KEY,Config.COS_APP_ID);


        if (cosUserInformation.getCOS_SECRET_ID().length() == 0|| cosUserInformation.getCOS_SECRET_KEY().length() == 0) {
            finish();
        }


        cosXmlService = CosServiceFactory.getCosXmlService(this, bucketRegion,
                cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), true);
        TransferConfig transferConfig = new TransferConfig.Builder().build();
        transferManager = new TransferManager(cosXmlService, transferConfig);
    }


    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btn_left) {
            if ("开始".contentEquals(btn_left.getText())) {
                download();
            } else if("取消".contentEquals(btn_left.getText())) {//取消
                if (cosxmlTask != null) {
                    cosxmlTask.cancel();
                    finish();
                } else {
                    toastMessage("操作失败");
                }
            }
        } else if (v.getId() == R.id.btn_right) {
            if ("暂停".contentEquals(btn_right.getText())) {
                if (cosxmlTask != null && cosxmlTask.getTaskState() == TransferState.IN_PROGRESS) {
                    cosxmlTask.pause();
                    btn_right.setText("恢复");
                } else {
                    toastMessage("操作失败");
                }
            } else {//恢复
                if (cosxmlTask != null && cosxmlTask.getTaskState() == TransferState.PAUSED) {
                    cosxmlTask.resume();
                    btn_right.setText("暂停");
                } else {
                    toastMessage("操作失败");
                }
            }
        }
    }

    /**
     * 刷新下载状态
     * @param state 状态 {@link TransferState}
     */
    private void refreshState(final TransferState state) {
        uiAction(new Runnable() {
            @Override
            public void run() {
                tv_state.setText(state.toString());
            }
        });
    }

    /**
     * 刷新下载进度
     * @param progress 已下载文件大小
     * @param total 文件总大小
     */
    private void refreshProgress(final long progress, final long total) {
        uiAction(new Runnable() {
            @SuppressLint("SetTextI18n")
            @Override
            public void run() {
                pb_download.setProgress((int) (100 * progress / total));
                tv_progress.setText(Utils.readableStorageSize(progress) + "/" + Utils.readableStorageSize(total));
            }
        });
    }

    private void download() {
        if (cosxmlTask == null) {
            String downloadPath = Environment.getExternalStorageDirectory()
                    + File.separator + Environment.DIRECTORY_DCIM
                    + File.separator + "cosdownload" + File.separator;
            cosxmlTask = transferManager.download(this, bucketName, download_key,
                    downloadPath,  filename);

            Log.e(TAG, "updown: "+ download_key);

            cosxmlTask.setTransferStateListener(new TransferStateListener() {
                @Override
                public void onStateChanged(final TransferState state) {
                    refreshState(state);
                }
            });

            cosxmlTask.setCosXmlProgressListener(new CosXmlProgressListener() {
                @Override
                public void onProgress(final long complete, final long target) {
                    refreshProgress(complete, target);
                }
            });

            cosxmlTask.setCosXmlResultListener(new CosXmlResultListener() {
                @SuppressLint("SetTextI18n")
                @Override
                public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                    cosxmlTask = null;
                    toastMessage("下载成功");

                    // 刷新android中的媒体库
                    File file = new File(downloadPath+filename);
                    MediaScannerConnection.scanFile(DownloadActivity.this, new String[] {file.getAbsolutePath()},null, null);

                    uiAction(new Runnable() {
                        @Override
                        public void run() {
                            btn_left.setVisibility(View.GONE);
                            btn_right.setVisibility(View.GONE);
                            tv_path.setText("加密图像已下载到：" + downloadPath + filename);
                        }
                    });
                }

                @Override
                public void onFail(CosXmlRequest request, CosXmlClientException exception, CosXmlServiceException serviceException) {
                    if (cosxmlTask.getTaskState() != TransferState.PAUSED) {
                        cosxmlTask = null;
                        toastMessage("下载失败");
                        uiAction(new Runnable() {
                            @Override
                            public void run() {
                                pb_download.setProgress(0);
                                tv_progress.setText("");
                                tv_state.setText("无");
                                btn_left.setText("开始");
                            }
                        });
                    }

                    if (exception != null) {
                        exception.printStackTrace();
                    }
                    if (serviceException != null) {
                        serviceException.printStackTrace();
                    }
                }
            });
            btn_left.setText("取消");
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (cosXmlService != null) {
            cosXmlService.release();
        }
    }


}
