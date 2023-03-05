package com.example.sca.ui.Share;

import android.content.Context;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.sca.R;

public class ShareFragment extends Fragment implements View.OnClickListener {
    private static final String TAG = "ShareFragment";
    private View root;
    private Button btn_urlrec;
    private EditText et_urlrec;
    private EditText et_keyrec;
    public Context sharecontext;
    private Button btn_keygen;
    private Button btn_keyrec;


    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        sharecontext = getActivity();

    }

    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {

        if (root == null) {
            root = inflater.inflate(R.layout.fragment_share, container, false);
        }

        et_urlrec = root.findViewById(R.id.et_urlrec);
        et_keyrec = root.findViewById(R.id.et_keyrec);
        btn_urlrec = root.findViewById(R.id.btn_urlrec);
        btn_keygen = root.findViewById(R.id.btn_keygen);
        btn_keyrec = root.findViewById(R.id.btn_keyrec);

        btn_keygen.setOnClickListener(this);
        btn_urlrec.setOnClickListener(this);
        btn_keyrec.setOnClickListener(this);

        // 设置显示菜单
        setHasOptionsMenu(true);
        return root;
    }


    @Override
    public void onDestroyView() {
        super.onDestroyView();
    }


    @Override
    public void onClick(View view) {
        if (view.getId() == R.id.btn_keygen) {
            Intent intent = new Intent(sharecontext, KeyGenActivity.class);
            startActivity(intent);
        } else if (view.getId() == R.id.btn_keyrec) {

            // save private key
            if (!TextUtils.isEmpty(et_keyrec.getText())) {
                String key = "";
                key += et_keyrec.getText();
                String priKey = key.substring(0, key.lastIndexOf("&"));

                String name = key.substring(key.lastIndexOf("&") + 1);
                Log.e(TAG, "priKey接收: "+ priKey );
                Log.e(TAG, "priKey接收长度： "+ priKey.length());


                if(!TextUtils.isEmpty(priKey)||!TextUtils.isEmpty(name)) {
                    SQLiteOpenHelper helper = MySqliteOpenHelper.getInstance(sharecontext);
                    SQLiteDatabase writableDatabase = helper.getWritableDatabase();
                    if (writableDatabase.isOpen()) {
                        writableDatabase.execSQL("replace into persons(nameID,privateKey)values(?,?)", new Object[]{name, priKey});
                    }
                    writableDatabase.close();
                    Log.e("私钥接受成功", "name: "+ name );
                    Toast.makeText(sharecontext, "密钥接受成功", Toast.LENGTH_SHORT).show();
                }
                else
                    Toast.makeText(sharecontext, "输入共享密钥有误", Toast.LENGTH_LONG).show();



            } else
                Toast.makeText(sharecontext, "请输入分享密钥", Toast.LENGTH_SHORT).show();

        } else {
            if (!TextUtils.isEmpty(et_urlrec.getText())) {
                String shareurl = et_urlrec.getText().toString();
                Intent intent = new Intent(sharecontext, ReceiveActivity.class);
                intent.putExtra(ReceiveActivity.ACTIVITY_EXTRA_SHARE_URL, shareurl);
                startActivity(intent);
            } else
                Toast.makeText(sharecontext, "请输入分享链接", Toast.LENGTH_SHORT).show();

        }
    }
}

