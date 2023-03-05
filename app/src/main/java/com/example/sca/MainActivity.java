package com.example.sca;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import com.example.sca.databinding.ActivityMainBinding;
import com.google.android.material.bottomnavigation.BottomNavigationView;


public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;
    private final int PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE = 10001;

    NavController navController = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);


        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());


        // 权限请求
        requestPermissions();


        BottomNavigationView navView = findViewById(R.id.nav_view);
        // Passing each menu ID as a set of Ids because each
        // menu should be considered as top level destinations.
        AppBarConfiguration appBarConfiguration = new AppBarConfiguration.Builder(
                R.id.navigation_local_image, R.id.navigation_cloud_image, R.id.navigation_share)
                .build();
        navController = Navigation.findNavController(this, R.id.nav_host_fragment_activity_main);
        NavigationUI.setupActionBarWithNavController(this, navController, appBarConfiguration);
        NavigationUI.setupWithNavController(binding.navView, navController);

    }
    @Override
    protected void onResume() {
        // 获取从其他Activity发送过来跳转Fragment的标志fragment_flag(名称随意)
        int fragmentFlag = this.getIntent().getIntExtra("fragment_flag", 0);
        switch (fragmentFlag){
            case 1:
                // 控制跳转到底部导航项(navigation_home为该Fragment的对应控件的id值)
                navController.navigate(R.id.navigation_local_image);
                break;
            case 2:
                navController.navigate(R.id.navigation_cloud_image);
                break;
            case 3:
                navController.navigate(R.id.navigation_share);
                break;

        }
        super.onResume();
    }

    private void requestPermissions() {
        if (ContextCompat.checkSelfPermission(this,
                Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {

            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                    PERMISSIONS_REQUEST_WRITE_EXTERNAL_STORAGE);
        }


    }


}