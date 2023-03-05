package com.example.sca.ui.cloud.backup;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import com.alibaba.sdk.android.oss.model.OSSBucketSummary;
import com.example.sca.R;

import java.util.List;

public class OssBackupAdapter extends BaseAdapter {
    private List<OSSBucketSummary> buckets;
    private Context context;

    public OssBackupAdapter(List<OSSBucketSummary> buckets, Context context) {
        this.buckets = buckets;
        this.context = context;
    }


    @Override
    public int getCount() {
        return buckets.size();
    }

    @Override
    public Object getItem(int position) {
        if (buckets != null && position >= 0 && position < buckets.size()) {
            return buckets.get(position);
        }
        return null;
    }

    @Override
    public long getItemId(int i) {
        return i;
    }

    @Override
    public View getView(int i, View view, ViewGroup viewGroup) {
        if(view == null){
            view = LayoutInflater.from(context).inflate(R.layout.bucket_item,viewGroup,false);

        }
        TextView tv_name = view.findViewById(R.id.tv_name);
        TextView tv_create_date = view.findViewById(R.id.tv_create_date);
        TextView tv_location = view.findViewById(R.id.tv_location);
        tv_name.setText(buckets.get(i).name);
        tv_create_date.setText(buckets.get(i).createDate.toString());
        tv_location.setText(buckets.get(i).location);


        return view;
    }
}
