package com.example.sca.ui.local.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.bumptech.glide.Glide;
import com.bumptech.glide.request.RequestOptions;
import com.example.sca.R;
import com.example.sca.ui.cloud.encryptalgorithm.AESUtils;

import java.util.ArrayList;


public class recyclerViewPagerImageIndicator extends RecyclerView.Adapter<indicatorHolder> {

    AESUtils aesUtils = new AESUtils();
    ArrayList<pictureFacer> pictureList;
    Context pictureContx;
    private final imageIndicatorListener imageListerner;

    /**
     *
     * @param pictureList ArrayList of pictureFacer objects
     * @param pictureContx The Activity of fragment context
     * @param imageListerner Interface for communication between adapter and fragment
     */
    public recyclerViewPagerImageIndicator(ArrayList<pictureFacer> pictureList, Context pictureContx, imageIndicatorListener imageListerner) {
        this.pictureList = pictureList;
        this.pictureContx = pictureContx;
        this.imageListerner = imageListerner;
    }


    @NonNull
    @Override
    public indicatorHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        View cell = inflater.inflate(R.layout.indicator_holder, parent, false);
        return new indicatorHolder(cell);
    }

    @SuppressLint("RecyclerView")
    @Override
    public void onBindViewHolder(@NonNull indicatorHolder holder, final int position) {

        final pictureFacer pic = pictureList.get(position);

        holder.positionController.setBackgroundColor(pic.getSelected() ? Color.parseColor("#00000000") : Color.parseColor("#8c000000"));

        String localPath = pic.getPicturePath();
        if(isImageFile(localPath)){ // 如果不是加密图片 ，则正常输出
            Glide.with(pictureContx)
                    .load(localPath)
                    .apply(new RequestOptions().centerCrop())
                    .into(holder.image);

        }else {// 如果是加密图片 ，则解密输出
            Bitmap decryptimage = aesUtils.decryptCTRFile(localPath,pictureContx);
            holder.image.setImageBitmap(decryptimage);
        }

        holder.image.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //holder.card.setCardElevation(5);
                pic.setSelected(true);
                notifyDataSetChanged();
                imageListerner.onImageIndicatorClicked(position);
            }
        });

    }

    @Override
    public int getItemCount() {
        return pictureList.size();
    }

    //图片格式判断
    public static boolean isImageFile(String path) {
        Bitmap drawable2 = BitmapFactory.decodeFile(path);
        return drawable2 != null;
    }
}
