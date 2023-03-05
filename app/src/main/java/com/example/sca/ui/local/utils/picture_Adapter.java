package com.example.sca.ui.local.utils;

import static androidx.core.view.ViewCompat.setTransitionName;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
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

/**
 * A RecyclerView Adapter class that's populates a RecyclerView with images from
 * a folder on the device external storage
 * 使用设备外部存储上文件夹中的图像填充RecyclerView的RecyclerView适配器类
 */
public class picture_Adapter extends RecyclerView.Adapter<PicHolder> {

    AESUtils aesUtils = new AESUtils();
    private ArrayList<pictureFacer> pictureList;
    private Context pictureContx;
    private final itemClickListener picListerner;

    /**
     *
     * @param pictureList ArrayList of pictureFacer objects
     * @param pictureContx The Activities Context
     * @param picListerner An interface for listening to clicks on the RecyclerView's items
     */
    public picture_Adapter(ArrayList<pictureFacer> pictureList, Context pictureContx,itemClickListener picListerner) {
        this.pictureList = pictureList;
        this.pictureContx = pictureContx;
        this.picListerner = picListerner;
    }

    @NonNull
    @Override
    public PicHolder onCreateViewHolder(@NonNull ViewGroup container, int position) {
        LayoutInflater inflater = LayoutInflater.from(container.getContext());
        View cell = inflater.inflate(R.layout.pic_holder_item, container, false);
        return new PicHolder(cell);
    }

    @Override
    public void onBindViewHolder(@NonNull final PicHolder holder, @SuppressLint("RecyclerView") final int position) {

        final pictureFacer image = pictureList.get(position);


        String localPath = image.getPicturePath();


        if(isImageFile(localPath)){ // 如果是图片，则直接输出
            Glide.with(pictureContx)
                    .load(localPath)
                    .apply(new RequestOptions().centerCrop())
                    .into(holder.picture);
        }else { //如果是加密图片，则解密
            Bitmap decryptimage = aesUtils.decryptCTRFile(localPath,pictureContx);
            holder.picture.setImageBitmap(decryptimage);
        }

        setTransitionName(holder.picture, String.valueOf(position) + "_image");

        holder.picture.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                picListerner.onPicClicked(holder,position, pictureList);
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
