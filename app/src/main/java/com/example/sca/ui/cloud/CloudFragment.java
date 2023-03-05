package com.example.sca.ui.cloud;


import static android.app.Activity.RESULT_OK;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.cloud.bucket.BucketAddActivity;
import com.example.sca.ui.cloud.bucket.BucketsAdapter;
import com.example.sca.ui.cloud.object.ObjectActivity;
import com.tencent.cos.xml.CosXmlService;
import com.tencent.cos.xml.exception.CosXmlClientException;
import com.tencent.cos.xml.exception.CosXmlServiceException;
import com.tencent.cos.xml.listener.CosXmlResultListener;
import com.tencent.cos.xml.model.CosXmlRequest;
import com.tencent.cos.xml.model.CosXmlResult;
import com.tencent.cos.xml.model.service.GetServiceRequest;
import com.tencent.cos.xml.model.service.GetServiceResult;
import com.tencent.cos.xml.model.tag.ListAllMyBuckets;

import java.util.List;

public class CloudFragment extends Fragment {

    private final int PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE = 10001;
    private final int REQUEST_ADD = 10003;
    private AlertDialog alertDialog;

    private CosXmlService cosXmlService;

    private ListView listview;
    private BucketsAdapter adapter;
    private CosUserInformation cosUserInformation;

    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {

        View root = inflater.inflate(
                R.layout.fragment_cloud, container, false );


        requestPermissions(); // 请求系统权限

        listview = root.findViewById(R.id.listview);
        listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                ListAllMyBuckets.Bucket bucket = adapter.getItem(position);
                if(bucket!=null){
                    Intent intent = new Intent(getActivity(), ObjectActivity.class);
                    intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME, bucket.name);
                    intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_REGION, bucket.location);
                    startActivity(intent);
                }
            }
        });

        cosUserInformation = new CosUserInformation(Config.COS_SECRET_ID,Config.COS_SECRET_KEY,Config.COS_APP_ID);


        if (cosUserInformation.getCOS_SECRET_ID().length() == 0 || cosUserInformation.getCOS_SECRET_KEY().length() == 0) {
            Toast.makeText(getActivity(), "请在环境变量中配置您的secretId和secretKey", Toast.LENGTH_SHORT).show();
        } else {
            cosXmlService = CosServiceFactory.getCosXmlService(getActivity(),
                    cosUserInformation.getCOS_SECRET_ID(), cosUserInformation.getCOS_SECRET_KEY(), false);

            getBuckets();// 查询存储桶列表
        }
        // 设置显示菜单
        setHasOptionsMenu(true);

        return root;

    }

    public void onCreateOptionsMenu(@NonNull Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.bucket, menu);
        menu.findItem(R.id.add).setVisible(true);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        if (item.getItemId() == R.id.add) {
            if (cosUserInformation.getCOS_APP_ID().length() == 0 ||
                    cosUserInformation.getCOS_SECRET_ID().length() == 0 ||
                    cosUserInformation.getCOS_SECRET_KEY().length() == 0) {
                Toast.makeText(getActivity(), "请在环境变量中配置您的secretId、secretKey、appid", Toast.LENGTH_SHORT).show();
            } else {
                startActivityForResult(new Intent(getActivity(), BucketAddActivity.class), REQUEST_ADD);
            }
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if(resultCode == RESULT_OK && requestCode == REQUEST_ADD){
            getBuckets();
        }
    }

    // 查询存储桶列表
    private void getBuckets(){
        showLoadingDialog();

        cosXmlService.getServiceAsync(new GetServiceRequest(), new CosXmlResultListener() {
            @Override
            public void onSuccess(CosXmlRequest request, final CosXmlResult result) {
                uiAction(new Runnable() {
                    @Override
                    public void run() {
                        dismissLoadingDialog();
                        List<ListAllMyBuckets.Bucket> buckets = ((GetServiceResult) result).listAllMyBuckets.buckets;
                        if(adapter==null){
                            adapter = new BucketsAdapter(buckets, getActivity());
                            listview.setAdapter(adapter);
                        } else {
                            adapter.setDataList(buckets);
                        }
                    }
                });
            }

            @Override
            public void onFail(CosXmlRequest request, CosXmlClientException exception, CosXmlServiceException serviceException) {
                dismissLoadingDialog();

                Toast.makeText(getActivity(), "获取存储桶列表失败", Toast.LENGTH_SHORT).show();
                if(exception!=null) {
                    exception.printStackTrace();
                }
                if(serviceException!=null) {
                    serviceException.printStackTrace();
                }
            }
        });
    }

    private void requestPermissions() {
        if (ContextCompat.checkSelfPermission(requireActivity(),
                Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {

            ActivityCompat.requestPermissions(requireActivity(),
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                    PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE: {
                if (grantResults.length == 0
                        || grantResults[0] != PackageManager.PERMISSION_GRANTED) {
                    ActivityCompat.requestPermissions(requireActivity(),
                            new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                            PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE);
                }
            }
        }
    }
    protected void uiAction(Runnable runnable){
        requireActivity().findViewById(android.R.id.content).post(runnable);
    }

    @SuppressLint("SetTextI18n")
    public void showLoadingDialog() {
        alertDialog = new AlertDialog.Builder(getActivity()).create();
        alertDialog.getWindow().setBackgroundDrawable(new ColorDrawable());
        alertDialog.setCancelable(false);
        alertDialog.setOnKeyListener(new DialogInterface.OnKeyListener() {
            @Override
            public boolean onKey(DialogInterface dialog, int keyCode, KeyEvent event) {
                if (keyCode == KeyEvent.KEYCODE_SEARCH || keyCode == KeyEvent.KEYCODE_BACK)
                    return true;
                return false;
            }
        });
        alertDialog.show();
        alertDialog.setContentView(R.layout.loading_alert);
        alertDialog.setCanceledOnTouchOutside(false);

    }

    public void dismissLoadingDialog() {
        if (null != alertDialog && alertDialog.isShowing()) {
            alertDialog.dismiss();
        }
    }


}
