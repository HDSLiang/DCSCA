package com.example.sca.ui.cloud;

public class CosUserInformation {
    private String COS_SECRET_ID;
    private String COS_SECRET_KEY;
    private String COS_APP_ID;

//    public void setCosUserInformation(String COS_SECRET_ID,String COS_SECRET_KEY,String COS_APP_ID) {
//        this.COS_SECRET_ID = COS_SECRET_ID;
//        this.COS_APP_ID = COS_APP_ID;
//        this.COS_SECRET_KEY = COS_SECRET_KEY;
//    }

    public CosUserInformation(String COS_SECRET_ID,String COS_SECRET_KEY,String COS_APP_ID){
        setCOS_APP_ID(COS_APP_ID.trim());
        setCOS_SECRET_ID(COS_SECRET_ID.trim());
        setCOS_SECRET_KEY(COS_SECRET_KEY.trim());
    }

    public void setCOS_APP_ID(String COS_APP_ID) {
        this.COS_APP_ID = COS_APP_ID;
    }

    public void setCOS_SECRET_ID(String COS_SECRET_ID) {
        this.COS_SECRET_ID = COS_SECRET_ID;
    }

    public void setCOS_SECRET_KEY(String COS_SECRET_KEY) {
        this.COS_SECRET_KEY = COS_SECRET_KEY;
    }

    public String getCOS_SECRET_ID() {
        return COS_SECRET_ID;
    }


    public String getCOS_SECRET_KEY() {
        return COS_SECRET_KEY;
    }


    public String getCOS_APP_ID() {
        return COS_APP_ID;
    }
}
