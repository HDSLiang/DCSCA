package com.example.sca.ui.local.utils;

/**
 *
 * Custom Class that holds information of a folder containing images
 * on the device external storage, used to populate our RecyclerView of
 * picture folders
 */
public class imageFolder {

    private  String path;
    private  String FolderName;
    private int numberOfPics = 0;
    private String firstPic;

    public imageFolder(){

    }

    public imageFolder(String path, String folderName) {
        this.path = path;
        FolderName = folderName;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getFolderName() {
        return FolderName;
    }

    public void setFolderName(String folderName) {
        FolderName = folderName;
    }

    public int getNumberOfPics() {
        return numberOfPics;
    }

    public void setNumberOfPics(int numberOfPics) {
        this.numberOfPics = numberOfPics;
    }

    public void addpics(){
        this.numberOfPics++;
    }

    public String getFirstPic() {
        return firstPic;
    }

    //此方法获取文件夹中第一张图片的路径。该图片在recyclerview适配器中用于表示整个文件夹
    public void setFirstPic(String firstPic) {
        this.firstPic = firstPic;
    }
}
