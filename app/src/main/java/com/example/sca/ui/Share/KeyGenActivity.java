package com.example.sca.ui.Share;


import static com.example.sca.ui.cloud.encryptalgorithm.HexStringAndByte.printHexString;

import android.annotation.SuppressLint;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.sca.Config;
import com.example.sca.R;
import com.example.sca.ui.cloud.encryptalgorithm.HexStringAndByte;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbePrivateKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeSecretMasterKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.Cpabe;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.policyparser.ParseException;

import java.io.IOException;

public class KeyGenActivity extends AppCompatActivity implements View.OnClickListener {
    private static final String TAG = "KeyGenActivity";
    private String attributes = ""; //用户属性

    private CheckBox cb_famliy;
    private CheckBox cb_goodfriends;
    private CheckBox cb_classmate;
    private CheckBox cb_colleague;
    private CheckBox cb_other;
    private Button btn_gen;
    private RadioGroup radgroup;
    private EditText et_name;
    private TextView tv_key;
    private String cos_app_id;


    @SuppressLint("Range")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_key_gen);

        cb_famliy = findViewById(R.id.cb_famliy);
        cb_goodfriends = findViewById(R.id.cb_goodfriends);
        cb_classmate = findViewById(R.id.cb_classmate);
        cb_colleague = findViewById(R.id.cb_colleague);
        cb_other = findViewById(R.id.cb_other);
        btn_gen = findViewById(R.id.btn_gen);
        radgroup = findViewById(R.id.radioGroup);
        et_name = findViewById(R.id.et_name);
        tv_key = findViewById(R.id.tv_key);


        cos_app_id = Config.COS_APP_ID;


        try {
            String s = printHexString(Cpabe.setup().getAsByteArray());
            Log.e(TAG, "s: " + s);
            // 数据库保存主密钥
            SQLiteOpenHelper helper = MySqliteOpenHelper.getInstance(this);
            SQLiteDatabase writableDatabase = helper.getWritableDatabase();
            if (writableDatabase.isOpen()) {
                writableDatabase.execSQL("insert or ignore into masters(nameID,masterKey)values(?,?)", new Object[]{cos_app_id, s});
            }
            writableDatabase.close();
        } catch (IOException e) {
            e.printStackTrace();
        }


        btn_gen.setOnClickListener(this);


    }


    @SuppressLint("Range")
    @Override
    public void onClick(View view) {

        // 关系部分
        if (cb_famliy.isChecked()) {
            attributes += cb_famliy.getText().toString() + " ";
        }
        if (cb_goodfriends.isChecked()) {
            attributes += cb_goodfriends.getText().toString() + " ";
        }
        if (cb_classmate.isChecked()) {
            attributes += cb_classmate.getText().toString() + " ";
        }
        if (cb_colleague.isChecked()) {
            attributes += cb_colleague.getText().toString() + " ";
        }
        if (cb_other.isChecked()) {
            attributes += cb_other.getText().toString() + " ";
        }

        // 性别部分
        for (int i = 0; i < radgroup.getChildCount(); i++) {
            RadioButton rd = (RadioButton) radgroup.getChildAt(i);
            if (rd.isChecked()) {
                attributes += rd.getText() + " ";
                break;
            }
        }

        //姓名部分
        if (!TextUtils.isEmpty(et_name.getText())) {
            attributes += et_name.getText();
            Log.e(TAG, "最终属性: " + attributes);


            try {
                //查询数据库主密钥
                String masterKey = "";
                SQLiteOpenHelper helper = MySqliteOpenHelper.getInstance(this);
                SQLiteDatabase readableDatabase = helper.getReadableDatabase();
                if (readableDatabase.isOpen()) {
                    Cursor cursor = readableDatabase.rawQuery("select * from masters where nameID=" + cos_app_id, null);
                    cursor.moveToFirst();
                    masterKey = cursor.getString(cursor.getColumnIndex("masterKey"));
                    cursor.close();
                    readableDatabase.close();
                }
                AbeSecretMasterKey smKey = AbeSecretMasterKey.readFromByteArray(HexStringAndByte.hexStringToByte(masterKey));
                Log.e(TAG, "smKey: " + smKey);
                AbePrivateKey userKey = Cpabe.keygenSingle(smKey, attributes);
                Log.e(TAG, "userKey: " + userKey);
                byte[] userKeybyte = userKey.getAsByteArray();
                String stringkey = printHexString(userKeybyte);
                String finallykey = stringkey + "&" + cos_app_id; // 私钥+APPID
                Log.e(TAG, "priKey生成: " + stringkey);
                Log.e(TAG, "priKey生成长度： " + stringkey.length());
                tv_key.setText(finallykey);
//                byte[] bytes = hexStringToByte(s);
//                AbePrivateKey abePrivateKey = readFromByteArray(bytes);
//                Log.e(TAG, "abePrivateKey: " + abePrivateKey);
            } catch (ParseException | IOException e) {
                e.printStackTrace();
            }


        } else
            Toast.makeText(this, "请输入姓名", Toast.LENGTH_SHORT).show();
    }




}