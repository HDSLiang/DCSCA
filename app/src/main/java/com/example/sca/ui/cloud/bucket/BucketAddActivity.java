package com.example.sca.ui.cloud.bucket;



import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.Nullable;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.OSS;
import com.alibaba.sdk.android.oss.OSSClient;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.auth.OSSPlainTextAKSKCredentialProvider;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.CreateBucketRequest;
import com.alibaba.sdk.android.oss.model.CreateBucketResult;
import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.cloud.CosServiceFactory;
import com.example.sca.ui.cloud.CosUserInformation;
import com.example.sca.ui.cloud.common.base.BaseActivity;
import com.example.sca.ui.cloud.region.RegionActivity;
import com.tencent.cos.xml.CosXmlService;
import com.tencent.cos.xml.exception.CosXmlClientException;
import com.tencent.cos.xml.exception.CosXmlServiceException;
import com.tencent.cos.xml.listener.CosXmlResultListener;
import com.tencent.cos.xml.model.CosXmlRequest;
import com.tencent.cos.xml.model.CosXmlResult;
import com.tencent.cos.xml.model.bucket.PutBucketRequest;

/**
 * Created by jordanqin on 2020/6/18.
 * 添加存储桶页面
 * <p>
 * Copyright (c) 2010-2020 Tencent Cloud. All rights reserved.
 */
public class BucketAddActivity extends BaseActivity implements View.OnClickListener {
    private final int REQUEST_REGION = 10001;

    private EditText et_name;
    private TextView tv_region;
    private String region;

    private CosUserInformation cosUserInformation;
    private CosXmlService cosXmlService;

    private OSSPlainTextAKSKCredentialProvider credentialProvider;
    private OSS ossClient;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.bucket_activity_add);

        et_name = findViewById(R.id.et_name);
        tv_region = findViewById(R.id.tv_region);

        findViewById(R.id.btn_add).setOnClickListener(this);
        findViewById(R.id.rl_region).setOnClickListener(this);

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
    }

    @Override
    public void onClick(View v) {
        if(v.getId()==R.id.rl_region){
            // 进入存储桶区域选择RegionActivity
            startActivityForResult(new Intent(this, RegionActivity.class), REQUEST_REGION);
        } else if(v.getId() == R.id.btn_add){
            // 创建一个主存储桶（ADD Bucket）
            addPrimaryBucket();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if(resultCode == RESULT_OK && requestCode == REQUEST_REGION && data!=null){
            String region = data.getStringExtra(RegionActivity.RESULT_REGION);
            String lable = data.getStringExtra(RegionActivity.RESULT_LABLE);
            if(!TextUtils.isEmpty(region) && !TextUtils.isEmpty(lable)){
                tv_region.setText(lable);
                this.region = region;
            }
        }
    }

    // 创建主云存储桶（ADD Bucket）
    private void addPrimaryBucket(){
        if(TextUtils.isEmpty(et_name.getText())){
            toastMessage("桶名称不能为空");
            return;
        }

        if(TextUtils.isEmpty(region)){
            toastMessage("请选择地区");
            return;
        }

        cosXmlService = CosServiceFactory.getCosXmlService(this, region, cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), true);
        showLoadingDialog();
        String bucket = et_name.getText() + "-" + cosUserInformation.getCOS_APP_ID(); // 存储桶名称，由bucketname-appid 组成，appid必须填入
        PutBucketRequest putBucketRequest = new PutBucketRequest(bucket);
        // 使用异步回调请求
        cosXmlService.putBucketAsync(putBucketRequest, new CosXmlResultListener() {
            @Override
            public void onSuccess(CosXmlRequest request, CosXmlResult result) {
                toastMessage("新建主存储桶成功");
                addBackupBucket();
            }

            @Override
            public void onFail(CosXmlRequest cosXmlRequest, CosXmlClientException clientException, CosXmlServiceException serviceException) {
                dismissLoadingDialog();
                toastMessage("新建主存储桶失败");
                if(clientException!=null) {
                    clientException.printStackTrace();
                }
                if(serviceException!=null) {
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

    // 创建备份云存储桶（ADD Bucket）
    private void addBackupBucket() {


        String bucket = et_name.getText() + "-" + cosUserInformation.getCOS_APP_ID(); // 存储桶名称，跟主云存储桶保持一致
        CreateBucketRequest createBucketRequest = new CreateBucketRequest(bucket);
        OSSAsyncTask createTask = ossClient.asyncCreateBucket(createBucketRequest, new OSSCompletedCallback<CreateBucketRequest, CreateBucketResult>() {
            @Override
            public void onSuccess(CreateBucketRequest request, CreateBucketResult result) {
                toastMessage("新建备份存储桶成功");
                dismissLoadingDialog();
                setResult(Activity.RESULT_OK);
                finish();
            }

            @Override
            public void onFailure(CreateBucketRequest request, ClientException clientException, ServiceException serviceException) {
                dismissLoadingDialog();
                toastMessage("新建备份存储桶失败");
                // 请求异常。
                if (clientException != null) {
                    // 本地异常如网络异常等。
                    clientException.printStackTrace();
                }
                if (serviceException != null) {

                    // 服务异常。
                    Log.e("ErrorCode", serviceException.getErrorCode());
                    Log.e("RequestId", serviceException.getRequestId());
                    Log.e("HostId", serviceException.getHostId());
                    Log.e("RawMessage", serviceException.getRawMessage());
                    Log.e("Message", serviceException.getMessage());

                }

            }
        });
    }


}
