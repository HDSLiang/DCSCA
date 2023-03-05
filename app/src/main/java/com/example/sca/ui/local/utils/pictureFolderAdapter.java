package com.example.sca.ui.local.utils;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.cardview.widget.CardView;
import androidx.recyclerview.widget.RecyclerView;

import com.example.sca.R;
import com.bumptech.glide.Glide;
import com.bumptech.glide.request.RequestOptions;
import com.example.sca.ui.cloud.encryptalgorithm.AESUtils;

import java.util.ArrayList;

/**
 * An adapter for populating RecyclerView with items representing folders that contain images
 * 用于向RecyclerView填充表示包含图像的文件夹的项的适配器
 */
public class pictureFolderAdapter extends RecyclerView.Adapter<pictureFolderAdapter.FolderHolder>{

    AESUtils aesUtils = new AESUtils();
    private ArrayList<imageFolder> folders;
    private Context folderContx;
    private itemClickListener listenToClick;

    /**
     *
     * @param folders An ArrayList of String that represents paths to folders on the external storage that contain pictures
     * @param folderContx The Activity or fragment Context
     * @param listen interFace for communication between adapter and fragment or activity
     */
    public pictureFolderAdapter(ArrayList<imageFolder> folders, Context folderContx, itemClickListener listen) {
        this.folders = folders;
        this.folderContx = folderContx;
        this.listenToClick = listen;
    }

    @NonNull
    @Override
    public FolderHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        View cell = inflater.inflate(R.layout.picture_folder_item, parent, false);
        return new FolderHolder(cell);

    }

    @Override
    public void onBindViewHolder(@NonNull FolderHolder holder, int position) {
        final imageFolder folder = folders.get(position);
        String firstPicPath = folder.getFirstPic();

        if(isImageFile(firstPicPath)){
            Glide.with(folderContx)
                    .load(firstPicPath)
                    .apply(new RequestOptions().centerCrop())
                    .into(holder.folderPic);

        }else{
            Bitmap bitmap = aesUtils.decryptCTRFile(firstPicPath,folderContx);
            holder.folderPic.setImageBitmap(bitmap);
        }



        //setting the number of images
        String text = ""+folder.getFolderName();
        String folderSizeString=""+folder.getNumberOfPics()+" Media";
        holder.folderSize.setText(folderSizeString);
        holder.folderName.setText(text);

        holder.folderPic.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                listenToClick.onPicClicked(folder.getPath(),folder.getFolderName());
            }
        });

    }

    @Override
    public int getItemCount() {
        return folders.size();
    }


    public class FolderHolder extends RecyclerView.ViewHolder{
        ImageView folderPic;
        TextView folderName;
        //set textview for foldersize
        TextView folderSize;

        CardView folderCard;

        public FolderHolder(@NonNull View itemView) {
            super(itemView);
            folderPic = itemView.findViewById(R.id.folderPic);
            folderName = itemView.findViewById(R.id.folderName);
            folderSize=itemView.findViewById(R.id.folderSize);
            folderCard = itemView.findViewById(R.id.folderCard);
        }
    }
    //图片格式判断
    public static boolean isImageFile(String path) {
        Bitmap drawable2 = BitmapFactory.decodeFile(path);
        return drawable2 != null;
    }

}
