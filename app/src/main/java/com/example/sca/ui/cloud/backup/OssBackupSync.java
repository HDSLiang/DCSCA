package com.example.sca.ui.cloud.backup;

import android.media.MediaScannerConnection;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;

import com.alibaba.sdk.android.oss.ClientConfiguration;
import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.OSS;
import com.alibaba.sdk.android.oss.OSSClient;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.OSSLog;
import com.alibaba.sdk.android.oss.common.auth.OSSPlainTextAKSKCredentialProvider;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.ListBucketsRequest;
import com.alibaba.sdk.android.oss.model.ListBucketsResult;
import com.alibaba.sdk.android.oss.model.ListObjectsRequest;
import com.alibaba.sdk.android.oss.model.ListObjectsResult;
import com.alibaba.sdk.android.oss.model.OSSBucketSummary;
import com.alibaba.sdk.android.oss.model.OSSObjectSummary;
import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.cloud.common.base.BaseActivity;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;

public class OssBackupSync extends BaseActivity {

    private ListView listView;

    private OSSPlainTextAKSKCredentialProvider credentialProvider;
    private OSS ossClient;
    private OssBackupAdapter adapter;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.backup_activity);
        listView = findViewById(R.id.lv_backup);


        credentialProvider = new OSSPlainTextAKSKCredentialProvider(Config.OSS_ACCESS_KEY_ID, Config.OSS_ACCESS_KEY_SECRET);
        ClientConfiguration config = new ClientConfiguration();

        ossClient = new OSSClient(this,credentialProvider,config);

        if (credentialProvider.getAccessKeyId().length() == 0 ||
                credentialProvider.getAccessKeySecret().length() == 0) {
            finish();
        }


        ListBucketsRequest request = new ListBucketsRequest();
        ListBucketsResult result = null;
        try {
             result = ossClient.listBuckets(request);

        } catch (ClientException e) {
            e.printStackTrace();
        } catch (ServiceException serviceException) {
            Log.e("ErrorCode", serviceException.getErrorCode());
            Log.e("RequestId", serviceException.getRequestId());
            Log.e("HostId", serviceException.getHostId());
            Log.e("RawMessage", serviceException.getRawMessage());
        }
        List<OSSBucketSummary> buckets = result.getBuckets();
        listView.setAdapter(new OssBackupAdapter(buckets, getApplicationContext()));


        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                String name = buckets.get(position).name;
                String location = buckets.get(position).location;
                sync(name,location);
            }
        });



    }

    private void sync(String name, String location) {
        OSS ossClient = new OSSClient(this, "https://"+location+".aliyuncs.com", credentialProvider);
        String localPath = Environment.getExternalStorageDirectory()
                + File.separator + Environment.DIRECTORY_DCIM
                + File.separator;

        ListObjectsRequest listObjectsRequest = new ListObjectsRequest(name);
        listObjectsRequest.setDelimiter("/"); //Delimiter 设置为 “/” 时，罗列该文件夹下的文件
        listObjectsRequest.setPrefix("picture/");

        ListObjectsResult listObjectsResult = null;
        try {
            listObjectsResult = ossClient.listObjects(listObjectsRequest);
        } catch (ClientException e) {
            e.printStackTrace();
        } catch (ServiceException serviceException) {
            // 服务异常。
            Log.e("ErrorCode", serviceException.getErrorCode());
            Log.e("RequestId", serviceException.getRequestId());
            Log.e("HostId", serviceException.getHostId());
            Log.e("RawMessage", serviceException.getRawMessage());
        }

        showLoadingDialog();
        if (listObjectsResult.getObjectSummaries().isEmpty())
        {
            toastMessage("此存储桶中无备份文件，请检查！");
            dismissLoadingDialog();
            return;
        }
        dismissLoadingDialog();


        Log.d("TAG", "size: "+listObjectsResult.getObjectSummaries().size());
        // 遍历所有Object:目录下的文件
        for (OSSObjectSummary objectSummary : listObjectsResult.getObjectSummaries()) {
            //path：fun/like/001.avi等，即：Bucket中存储文件的路径
            String path = objectSummary.getKey();
            Log.d("TAG", "download: "+ path);
            //判断文件所在本地路径是否存在，若无，新建目录
            File file = new File(localPath + path);
            File fileParent = file.getParentFile();
            if (!fileParent.exists()) {
                fileParent.mkdirs();
            }


            // 构造下载文件请求。
            GetObjectRequest get = new GetObjectRequest(name, path);

            ossClient.asyncGetObject(get, new OSSCompletedCallback<GetObjectRequest, GetObjectResult>() {
                @Override
                public void onSuccess(GetObjectRequest request, GetObjectResult result) {
                    // 开始读取数据。
                    long length = result.getContentLength();
                    if (length > 0) {
                        byte[] buffer = new byte[(int) length];
                        int readCount = 0;
                        while (readCount < length) {
                            try{
                                readCount += result.getObjectContent().read(buffer, readCount, (int) length - readCount);
                            }catch (Exception e){
                                OSSLog.logInfo(e.toString());
                            }
                        }
                        // 将下载后的文件存放在指定的本地路径，例如D:\\localpath\\exampleobject.jpg。
                        try {
                            FileOutputStream fout = new FileOutputStream(localPath + path );
                            fout.write(buffer);
                            fout.close();
                        } catch (Exception e) {
                            OSSLog.logInfo(e.toString());
                        }
                    }
                    // 刷新android中的媒体库
                    MediaScannerConnection.scanFile(OssBackupSync.this, new String[] {file.getAbsolutePath()},null, null);

                }

                @Override
                public void onFailure(GetObjectRequest request, ClientException clientException,
                                      ServiceException serviceException)  {
                    // 请求异常。
                    if (clientException != null) {
                        // 本地异常，如网络异常等。
                        clientException.printStackTrace();
                    }
                    if (serviceException != null) {
                        // 服务异常。
                        Log.e("ErrorCode", serviceException.getErrorCode());
                        Log.e("RequestId", serviceException.getRequestId());
                        Log.e("HostId", serviceException.getHostId());
                        Log.e("RawMessage", serviceException.getRawMessage());
                    }

                }
            });

        }
    }


}
