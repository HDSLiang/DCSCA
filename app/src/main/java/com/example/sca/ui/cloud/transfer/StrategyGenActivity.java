package com.example.sca.ui.cloud.transfer;

import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_IMAGE_NAME;
import static com.example.sca.ui.cloud.object.ObjectActivity.ACTIVITY_EXTRA_REGION;

import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.sca.R;
import com.example.sca.ui.cloud.object.ObjectActivity;

public class StrategyGenActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String TAG = "StrategyGenActivity";
    private String attributes = ""; //策略属性

    private CheckBox cb_famliy;
    private CheckBox cb_goodfriends;
    private CheckBox cb_classmate;
    private CheckBox cb_colleague;
    private CheckBox cb_other;
    private Button btn_gen;
    private RadioGroup radgroup;
    private EditText et_name;

    private String bucketName;
    private String bucketRegion;
    private String sourcecosPath;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_strategy_gen);

        cb_famliy =findViewById(R.id.cb_famliy1);
        cb_goodfriends =findViewById(R.id.cb_goodfriends1);
        cb_classmate =findViewById(R.id.cb_classmate1);
        cb_colleague =findViewById(R.id.cb_colleague1);
        cb_other =findViewById(R.id.cb_other1);
        btn_gen=findViewById(R.id.btn_gen1);
        radgroup =findViewById(R.id.radioGroup1);
        et_name =findViewById(R.id.et_name1);

        btn_gen.setOnClickListener(this);


        bucketName = getIntent().getStringExtra(ACTIVITY_EXTRA_BUCKET_NAME);
        bucketRegion = getIntent().getStringExtra(ACTIVITY_EXTRA_REGION);
        sourcecosPath = getIntent().getStringExtra(ACTIVITY_EXTRA_IMAGE_NAME);


    }

    @Override
    public void onClick(View view) {
        // 关系部分
        String relationshipAttributes = "";
        if (cb_famliy.isChecked()) {
            relationshipAttributes += cb_famliy.getText().toString() + " ";
        }
        if (cb_goodfriends.isChecked()) {
            if(!TextUtils.isEmpty(relationshipAttributes))
                relationshipAttributes =relationshipAttributes+ "or "+ cb_goodfriends.getText().toString() + " ";
            else  attributes += cb_goodfriends.getText().toString() + " ";


        }
        if (cb_classmate.isChecked()) {
            if(!TextUtils.isEmpty(relationshipAttributes))
                relationshipAttributes =relationshipAttributes+ "or "+ cb_classmate.getText().toString() + " ";
            else
                relationshipAttributes += cb_classmate.getText().toString() + " ";
        }
        if (cb_colleague.isChecked()) {
            if(!TextUtils.isEmpty(relationshipAttributes))
                relationshipAttributes =relationshipAttributes+ "or "+ cb_colleague.getText().toString() + " ";
            else
                relationshipAttributes += cb_colleague.getText().toString() + " ";
        }
        if (cb_other.isChecked()) {
            if(!TextUtils.isEmpty(relationshipAttributes))
                relationshipAttributes =relationshipAttributes+ "or "+ cb_other.getText().toString() + " ";
            else
                relationshipAttributes += cb_other.getText().toString() + " ";
        }

        // 性别部分
        String genderAttributes = "";
        for (int i = 0; i < radgroup.getChildCount(); i++) {
            RadioButton rd = (RadioButton) radgroup.getChildAt(i);
            if (rd.isChecked()) {
                if(rd.getText()!="unlimited")  genderAttributes += rd.getText() + " ";
                break;
            }
        }


        // 姓名部分
        String nameAttributes = et_name.getText().toString();

        //最终属性条件语句生成
        if(TextUtils.isEmpty(relationshipAttributes))
            Toast.makeText(this, "关系属性不能为空，请勾选关系属性", Toast.LENGTH_LONG).show();
        else
            attributes = "("+relationshipAttributes+")";

        if(!TextUtils.isEmpty(genderAttributes))
            attributes = attributes + " and "+ genderAttributes;

        if (!TextUtils.isEmpty(nameAttributes))
            attributes = "("+attributes+")" + " or "+ nameAttributes;


        Log.e(TAG, "attributes: "+ attributes );

        Intent intent = new Intent(this, ShareActivity.class);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_BUCKET_NAME, bucketName);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_REGION, bucketRegion);
        intent.putExtra(ObjectActivity.ACTIVITY_EXTRA_IMAGE_NAME, sourcecosPath);
        intent.putExtra(ShareActivity.ACTIVITY_SHARE_STRATEGY, attributes);
        startActivity(intent);



    }
}