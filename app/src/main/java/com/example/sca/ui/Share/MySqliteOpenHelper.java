package com.example.sca.ui.Share;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import androidx.annotation.Nullable;

/**
 * MySqliteOpenHelper toolclass
 */

public class MySqliteOpenHelper extends SQLiteOpenHelper {
    private static SQLiteOpenHelper mInstance;
    public static synchronized SQLiteOpenHelper getInstance(Context context){
        if(mInstance==null){
            mInstance = new MySqliteOpenHelper(context,"keySave.db",null,1);
        }
        return mInstance;
    }



    private MySqliteOpenHelper(@Nullable Context context, @Nullable String name, @Nullable SQLiteDatabase.CursorFactory factory, int version) {
        super(context, name, factory, version);
    }


    //数据库初始化
    @Override
    public void onCreate(SQLiteDatabase sqLiteDatabase) {

        String sql = "create table persons(_id INTEGER primary key autoincrement, nameID TEXT UNIQUE ,privateKey TEXT)";
        String sql2 = "create table masters(_id INTEGER primary key autoincrement, nameID TEXT UNIQUE ,masterKey TEXT)";
        sqLiteDatabase.execSQL(sql);
        sqLiteDatabase.execSQL(sql2);

    }

    //数据库升级
    @Override
    public void onUpgrade(SQLiteDatabase sqLiteDatabase, int i, int i1) {

    }

}
