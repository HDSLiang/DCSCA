package com.example.sca.ui.cloud.region;

import android.content.Context;
import android.widget.TextView;

import com.example.sca.R;
import com.example.sca.ui.cloud.common.base.BaseAbstractAdapter;

import java.util.List;

/**
 * Created by jordanqin on 2020/6/18.
 * 区域数据适配器
 * <p>
 * Copyright (c) 2010-2020 Tencent Cloud. All rights reserved.
 */
public class RegionAdapter extends BaseAbstractAdapter<RegionEntity> {
    public RegionAdapter(List<RegionEntity> list, Context context) {
        super(list, context);
    }

    @Override
    protected int getItemLayoutId(int type) {
        return R.layout.region_item;
    }

    @Override
    protected void inflate(final RegionEntity entity, int position) {
        TextView tv_lable = findViewById(R.id.tv_lable);

        tv_lable.setText(entity.getLabel());
    }
}
