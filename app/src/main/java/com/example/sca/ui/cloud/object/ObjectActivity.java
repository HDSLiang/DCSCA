package com.example.sca.ui.cloud.object;


import android.annotation.SuppressLint;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.AbsListView;
import android.widget.ListView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.OSS;
import com.alibaba.sdk.android.oss.OSSClient;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.auth.OSSPlainTextAKSKCredentialProvider;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.DeleteObjectResult;
import com.example.sca.Config;
import com.example.sca.MainActivity;
import com.example.sca.R;
import com.example.sca.ui.cloud.CloudImageDisplay;
import com.example.sca.ui.cloud.CosServiceFactory;
import com.example.sca.ui.cloud.CosUserInformation;
import com.example.sca.ui.cloud.common.base.BaseActivity;
import com.example.sca.ui.cloud.transfer.DownloadActivity;
import com.example.sca.ui.cloud.transfer.StrategyGenActivity;
import com.example.sca.ui.cloud.transfer.UploadActivity;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.tencent.cos.xml.CosXmlService;
import com.tencent.cos.xml.exception.CosXmlClientException;
import com.tencent.cos.xml.exception.CosXmlServiceException;
import com.tencent.cos.xml.listener.CosXmlResultListener;
import com.tencent.cos.xml.model.CosXmlRequest;
import com.tencent.cos.xml.model.CosXmlResult;
import com.tencent.cos.xml.model.bucket.GetBucketRequest;
import com.tencent.cos.xml.model.bucket.GetBucketResult;
import com.tencent.cos.xml.model.object.DeleteObjectRequest;

/**
 * Created by jordanqin on 2020/6/18.
 * 对象列表页
 * <p>
 * Copyright (c) 2010-2020 Tencent Cloud. All rights reserved.
 */
public class ObjectActivity extends BaseActivity implements AbsListView.OnScrollListener, ObjectAdapter.OnObjectListener {
    public final static String ACTIVITY_EXTRA_BUCKET_NAME = "bucket_name";
    public final static String ACTIVITY_EXTRA_FOLDER_NAME = "folder_name";
    public final static String ACTIVITY_EXTRA_REGION = "bucket_region";
    public final static String ACTIVITY_EXTRA_DOWNLOAD_KEY = "download_key";
    public final static String ACTIVITY_EXTRA_IMAGE_NAME = "image_name";
    private static final String TAG = "ObjectActivity";

    private final int REQUEST_UPLOAD = 10001;
    private int count = 0;  //添加一个count变量(初始值为零) ，使程序忽略由setSelectedItemId()而触发的第一次界面跳转

    private ListView listview;
    private ObjectAdapter adapter;
    private TextView footerView;
    private BottomNavigationView navview1;
    //是否到底部
    private boolean isBottom;
    //分页标示
    private String marker;
    //是否截断（用来判断分页数据是否完全加载）
    private boolean isTruncated;

    private String bucketName;
    private String folderName;
    private String bucketRegion;
    private CosUserInformation cosUserInformation;
    private CosXmlService cosXmlService;

    private OSSPlainTextAKSKCredentialProvider credentialProvider;
    private OSS ossClient;

    // 底部导航栏图标选中跳转到fragment寄生的activity，再从activity跳转至对应的activity
    private final BottomNavigationView.OnNavigationItemSelectedListener mOnNavigationItemSelectedListener
            = new BottomNavigationView.OnNavigationItemSelectedListener() {

        @SuppressLint("NonConstantResourceId")
        @Override
        public boolean onNavigationItemSelected(@NonNull MenuItem item) {
            Intent intent = new Intent(ObjectActivity.this, MainActivity.class);
            // 重用对应activity，并清除栈内activity
//            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP|Intent.FLAG_ACTIVITY_CLEAR_TOP );
            switch (item.getItemId()) {
                case R.id.navigation_local_image:
                    intent.putExtra("fragment_flag",1);
                    startActivity(intent);
                    return true;
                case R.id.navigation_cloud_image:
                    count++;
                    if(count>1) {
                        intent.putExtra("fragment_flag",2);
                        startActivity(intent);
                    }
                    return true;
                case R.id.navigation_share:
                    intent.putExtra("fragment_flag",3);
                    startActivity(intent);
                    return true;
            }
            return false;
        }
    };


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.base_list_activity);

        bucketName = getIntent().getStringExtra(ACTIVITY_EXTRA_BUCKET_NAME);
        folderName = getIntent().getStringExtra(ACTIVITY_EXTRA_FOLDER_NAME);
        bucketRegion = getIntent().getStringExtra(ACTIVITY_EXTRA_REGION);

        if (getSupportActionBar() != null) {
            if (TextUtils.isEmpty(folderName)) {
                getSupportActionBar().setTitle(bucketName);
            } else {
                getSupportActionBar().setTitle(folderName);
            }
        }
        navview1 = findViewById(R.id.nav_view1);
        navview1.setOnNavigationItemSelectedListener(mOnNavigationItemSelectedListener);

        // 下面这行代码会导致触发onNavigationItemSelected函数从而一直跳转到云端初始界面
        // 所以添加一个count变量 ，使程序忽略由setSelectedItemId()而触发的第一次界面跳转
        navview1.setSelectedItemId(R.id.navigation_cloud_image);


        listview = findViewById(R.id.listview);
        listview.setOnScrollListener(this);
        footerView = new TextView(this);
        AbsListView.LayoutParams params = new AbsListView.LayoutParams(AbsListView.LayoutParams.MATCH_PARENT, AbsListView.LayoutParams.WRAP_CONTENT);
        footerView.setPadding(0, 30, 0, 30);
        footerView.setLayoutParams(params);
        footerView.setGravity(Gravity.CENTER);
        footerView.setTextColor(Color.parseColor("#666666"));
        footerView.setTextSize(16);
        listview.setFooterDividersEnabled(false);
        listview.addFooterView(footerView);



        cosUserInformation = new CosUserInformation(Config.COS_SECRET_ID,Config.COS_SECRET_KEY,Config.COS_APP_ID);

        credentialProvider = new OSSPlainTextAKSKCredentialProvider(Config.OSS_ACCESS_KEY_ID,Config.OSS_ACCESS_KEY_SECRET);
        ossClient = new OSSClient(this,Config.OSS_ENDPOINT,credentialProvider); // 备份云存储桶地域固定为 endpoint 中的地域

        if (cosUserInformation.getCOS_SECRET_ID().length() == 0 || cosUserInformation.getCOS_SECRET_KEY().length() == 0 ||
                TextUtils.isEmpty(bucketRegion)||credentialProvider.getAccessKeyId().length() == 0 ||
                credentialProvider.getAccessKeySecret().length() == 0) {
            finish();
        } else {
            cosXmlService = CosServiceFactory.getCosXmlService(this, bucketRegion, cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), true);
            getObject();

        }




    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.object, menu);
        return super.onCreateOptionsMenu(menu);
    }

    // 点击上传到上传界面
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.upload) {
            Intent intent = new Intent(this, UploadActivity.class);
            intent.putExtra(ACTIVITY_EXTRA_REGION, bucketRegion);
            intent.putExtra(ACTIVITY_EXTRA_BUCKET_NAME, bucketName);
            intent.putExtra(ACTIVITY_EXTRA_FOLDER_NAME, folderName);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP ); // 清除栈顶activity
            startActivity(intent);

            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == RESULT_OK && requestCode == REQUEST_UPLOAD) {
            marker = null;
            getObject();
        }

    }

    private void getObject() {
        String bucketName = this.bucketName;
        final GetBucketRequest getBucketRequest = new GetBucketRequest(bucketName);

        // 前缀匹配，用来规定返回的对象前缀地址
        if (!TextUtils.isEmpty(folderName)) {
            getBucketRequest.setPrefix(folderName);
        } else {
            getBucketRequest.setPrefix("picture/");
        }

        // 如果是第一次调用，您无需设置 marker 参数，COS 会从头开始列出对象
        // 如果需列出下一页对象，则需要将 marker 设置为上次列出对象时返回的 GetBucketResult.listBucket.nextMarker 值
        // 如果返回的 GetBucketResult.listBucket.isTruncated 为 false，则说明您已经列出了所有满足条件的对象
        if (!TextUtils.isEmpty(marker)) {
            getBucketRequest.setMarker(marker);
        }

        // 单次返回最大的条目数量，默认1000
        getBucketRequest.setMaxKeys(100);

        // 定界符为一个符号，如果有 Prefix，
        // 则将 Prefix 到 delimiter 之间的相同路径归为一类，定义为 Common Prefix，
        // 然后列出所有 Common Prefix。如果没有 Prefix，则从路径起点开始
        getBucketRequest.setDelimiter("/");

        //首页加载弹窗loading  非首页底部loading
        if (TextUtils.isEmpty(marker)) {
            showLoadingDialog();
        } else {
            footerView.setText("正在加载数据...");
        }

        // 使用异步回调请求
        cosXmlService.getBucketAsync(getBucketRequest, new CosXmlResultListener() {
            @Override
            public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                final GetBucketResult getBucketResult = (GetBucketResult) result;
                isTruncated = getBucketResult.listBucket.isTruncated;

                uiAction(new Runnable() {
                    @Override
                    public void run() {
                        //首页加载弹窗loading  非首页底部loading
                        if (TextUtils.isEmpty(marker)) {
                            dismissLoadingDialog();
                        }
                        if (!isTruncated) {
                            footerView.setText("无更多数据");
                        }

                        marker = getBucketResult.listBucket.nextMarker;
                        if (adapter == null) {
                            adapter = new ObjectAdapter(ObjectEntity.listBucket2ObjectList(getBucketResult.listBucket, folderName),
                                    ObjectActivity.this, ObjectActivity.this, folderName);
                            listview.setAdapter(adapter);
                        } else {
                            //首页加载弹窗loading  非首页底部loading
                            if (TextUtils.isEmpty(marker)) {
                                adapter.setDataList(ObjectEntity.listBucket2ObjectList(getBucketResult.listBucket, folderName));
                            } else {
                                adapter.addDataList(ObjectEntity.listBucket2ObjectList(getBucketResult.listBucket, folderName));
                            }
                        }

                    }
                });
            }

            @Override
            public void onFail(CosXmlRequest cosXmlRequest, CosXmlClientException clientException, CosXmlServiceException serviceException) {
                //首页加载弹窗loading  非首页底部loading
                if (TextUtils.isEmpty(marker)) {
                    dismissLoadingDialog();
                    toastMessage("获取对象列表失败");
                } else {
                    footerView.setText("获取对象列表失败");
                }

                if (clientException != null) {
                    clientException.printStackTrace();
                }
                if (serviceException != null) {
//                    serviceException.printStackTrace();
                    // 服务异常。
                    Log.e("ErrorCode", serviceException.getErrorCode());
                    Log.e("RequestId", serviceException.getRequestId());
                    Log.e("HttpMessage", serviceException.getHttpMessage());
                    Log.e("Message", serviceException.getMessage());
                }
            }
        });
    }

    @Override
    public void onScrollStateChanged(AbsListView view, int scrollState) {
        //滑动停止后开始请求数据
        if (scrollState == AbsListView.OnScrollListener.SCROLL_STATE_IDLE) {
            if (isBottom && isTruncated && !TextUtils.isEmpty(marker)) {
                getObject();
            }
        }
    }

    @Override
    public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
        //是否滑动到底部
        if (firstVisibleItem + visibleItemCount == totalItemCount) {
            isBottom = true;
        } else {
            isBottom = false;
        }
    }

    @Override
    public void onFolderClick(String prefix) {
        Intent intent = new Intent(this, ObjectActivity.class);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME, bucketName);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_REGION, bucketRegion);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_FOLDER_NAME, prefix);
        startActivity(intent);
    }

    @Override
    public void onDownload(final ObjectEntity object) {
        Intent intent = new Intent(this, DownloadActivity.class);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME, bucketName);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_REGION, bucketRegion);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_DOWNLOAD_KEY, object.getContents().key);
        startActivity(intent);
    }

    @Override
    public void onDisplay(ObjectEntity object) {
        Intent intent = new Intent(this, CloudImageDisplay.class);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME, bucketName);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_REGION, bucketRegion);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_IMAGE_NAME, object.getContents().key);
        Log.e(TAG, "sourceKey: " + object.getContents().key);
        startActivity(intent);
    }

    @Override
    public void onDelete(final ObjectEntity object) {
        String bucket = this.bucketName;

        DeleteObjectRequest deleteObjectRequest = new DeleteObjectRequest(bucket, object.getContents().key);

        dismissLoadingDialog();
        cosXmlService.deleteObjectAsync(deleteObjectRequest, new CosXmlResultListener() {
            @Override
            public void onSuccess(CosXmlRequest cosXmlRequest, CosXmlResult result) {
                uiAction(new Runnable() {
                    @Override
                    public void run() {
                        adapter.delete(object);
                    }
                });
                ossDelete(bucket,object.getContents().key);
            }

            @Override
            public void onFail(CosXmlRequest cosXmlRequest, CosXmlClientException clientException, CosXmlServiceException serviceException) {
                dismissLoadingDialog();
                toastMessage("删除对象失败");
                if (clientException != null) {
                    clientException.printStackTrace();
                }
                if (serviceException != null) {
                    // 服务异常。
                    Log.e("ErrorCode", serviceException.getErrorCode());
                    Log.e("RequestId", serviceException.getRequestId());
                    Log.e("HttpMessage", serviceException.getHttpMessage());
                    Log.e("Message", serviceException.getMessage());
                }
            }
        });
    }



    @Override
    public void onShare(ObjectEntity object) {

        Intent intent = new Intent(this, StrategyGenActivity.class);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME, bucketName);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_REGION, bucketRegion);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_IMAGE_NAME, object.getContents().key);
        startActivity(intent);

    }

    private void ossDelete(String bucketname, String path) {
        com.alibaba.sdk.android.oss.model.DeleteObjectRequest delete = new com.alibaba.sdk.android.oss.model.DeleteObjectRequest(bucketname,path);
        OSSAsyncTask deleteTask = ossClient.asyncDeleteObject(delete, new OSSCompletedCallback<com.alibaba.sdk.android.oss.model.DeleteObjectRequest, DeleteObjectResult>() {
            @Override
            public void onSuccess(com.alibaba.sdk.android.oss.model.DeleteObjectRequest request, DeleteObjectResult result) {
                toastMessage("删除对象成功");
                uiAction(new Runnable() {
                    @Override
                    public void run() {
                        showLoadingDialog();
                    }
                });
            }

            @Override
            public void onFailure(com.alibaba.sdk.android.oss.model.DeleteObjectRequest request, ClientException clientException, ServiceException serviceException) {
                dismissLoadingDialog();;
                toastMessage("删除对象失败");
                // 请求异常。
                if (clientException != null) {
                    // 客户端异常，例如网络异常等。
                    clientException.printStackTrace();
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



}
