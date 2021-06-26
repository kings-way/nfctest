package io.stdio.nfctest;


import android.view.View;
import android.os.Bundle;
import android.os.Vibrator;
import android.app.Service;
import android.content.Intent;
import android.app.PendingIntent;
import android.text.method.ScrollingMovementMethod;
import androidx.appcompat.app.AppCompatActivity;

import android.widget.EditText;
import android.widget.Toast;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.ArrayAdapter;

import android.nfc.Tag;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.nfc.tech.IsoDep;
import android.nfc.NfcAdapter;


public class MainActivity extends AppCompatActivity {
    private NfcA tagA;
    private NfcB tagB;
    private IsoDep tagISO;
    private static final String[] tag_techs = {"NfcA (ISO 14443-3A)", "NfcB (ISO-14443-3B)", "IsoDep (ISO14443-4)", "Mifare Classic"};

    // select MF
    byte[] CPU_SELECT_MF = {0x00, (byte) 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x00};

    // select DF, name: Bostex4009600899
    byte[] CPU_SELECT_DF = {0x00, (byte)0xA4, 0x04, 0x00,0x10,0x42,0x6F,0x73,0x74,0x65,0x78,0x34,0x30,0x30,0x39,0x36,0x30,0x30,0x38,0x39,0x39};

    // DF Inner Auth, send 8 bytes random data: 0x31,0x8F,0xB4,0x73,0x9F,0xD1,0x65,0x48
    byte[] CPU_DF_INNER_AUTH = {0x00,(byte)0x88,0x00,0x00,0x08,0x31,(byte)0x8F,(byte)0xB4,0x73,(byte)0x9F,(byte)0xD1,0x65,0x48};

    // Read binary file. Note: 0x15 (0x95 = 0x80 | 0x15)
    byte[] CPU_READ_DF = {0x00,(byte)0xB0,(byte)0x95,0x00,0x21};



    private TextView tv_log;
    private Button bt_send;
    private EditText et_input;
    private Spinner spinner_type;
    private Vibrator vibrator;
    private NfcAdapter nfc_adapter;
    private ArrayAdapter<String> array_adapter;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tv_log = findViewById(R.id.tv_log);
        bt_send = findViewById(R.id.bt_send);
        et_input = findViewById(R.id.et_input);
        tv_log.setMovementMethod(ScrollingMovementMethod.getInstance());
        spinner_type = findViewById(R.id.spinner_cardtype);

        // set spinner data
        array_adapter = new ArrayAdapter<String>(this,android.R.layout.simple_spinner_item,tag_techs);
        array_adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner_type.setAdapter(array_adapter);
        spinner_type.setVisibility(View.VISIBLE);

        vibrator=(Vibrator)getSystemService(Service.VIBRATOR_SERVICE);
        nfc_adapter = NfcAdapter.getDefaultAdapter(getApplicationContext());

        addListenerOnButton();
    }

    @Override
    protected void onResume(){
        super.onResume();
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        nfc_adapter.enableForegroundDispatch(this, pendingIntent, null, null);

    }

    @Override
    protected void onPause(){
        super.onPause();
        nfc_adapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        autoReadCard(intent);
    }

    public void transceive_tagA(byte[] data){
        if(!tagA.isConnected()){
            log("NfcA not connected, quitting...");
            return;
        }
        try {
            log(">> " + bytes2hex(data));
            log("<< " + bytes2hex(tagA.transceive(data)));
        }catch (Exception e){
            e.printStackTrace();
            log(e.toString());
        }
    }


    public void transceive_tagB(byte[] data){
        if(!tagB.isConnected()){
            log("NfcB not connected, quitting...");
            return;
        }
        try {
            log(">> " + bytes2hex(data));
            log("<< " + bytes2hex(tagB.transceive(data)));
        }catch (Exception e){
            e.printStackTrace();
            log(e.toString());
        }
    }

    public void transceive_IsoDep(byte[] data){
        if(!tagISO.isConnected()){
            log("IsoDep not connected, quitting...");
            return;
        }
        try {
            log(">> " + bytes2hex(data));
            log("<< " + bytes2hex(tagISO.transceive(data)));
        }catch (Exception e){
            e.printStackTrace();
            log(e.toString());
        }
    }


    public void do_NfcA(){
        try {
            if ( ! tagA.isConnected()){
                log("NfcA not connected, now to connect...");
                tagA.connect();
            }

            log("\n# Send RATS  ");
            transceive_tagA(new byte[]{(byte)0xe0,0x51});

        }catch (Exception e){
            e.printStackTrace();
            log(e.toString());
        }
    }

    public void do_NfcB() {
        try {
            if (!tagB.isConnected()) {
                log("NfcB not connected, now to connect...");
                tagB.connect();
            }

            log("\n# Query Chinese ID Card No");
            transceive_tagB(new byte[]{0x00,0x36,0x00,0x00,0x08});

        } catch (Exception e) {
            e.printStackTrace();
            log(e.toString());
        }
    }
        public void do_IsoDep(){
        try {
            if ( ! tagISO.isConnected()){
                log("IsoDep not connected, now to connect...");
                tagISO.connect();
            }
            log("\n# SELECT MF");
            transceive_IsoDep(CPU_SELECT_MF);

            log("\n# SELECT DF (Bostex4009600899)");
            transceive_IsoDep(CPU_SELECT_DF);

            log("\n# DF Inner Auth");
            transceive_IsoDep(CPU_DF_INNER_AUTH);

            log("\n# Read Binary (fileNote 0015)");
            transceive_IsoDep(CPU_READ_DF);
        }catch (Exception e){
            e.printStackTrace();
            log(e.toString());
        }
    }

    private void autoReadCard(Intent intent){
        vibrator.vibrate(100);
        Toast.makeText(this,"NFC Card Detected...", Toast.LENGTH_SHORT ).show();

        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if(tag != null) {
            try {
                log("UID:" + bytes2hex(tag.getId()));
                for (String i:tag.getTechList())
                    log('[' + i + ']');
                log("=================================");

                switch (spinner_type.getSelectedItemPosition()){
                    case 0:
                        tagA = NfcA.get(tag);
                        do_NfcA();
                        break;

                    case 1:
                        tagB = NfcB.get(tag);
                        do_NfcB();
                        break;

                    case 2:
                        tagISO = IsoDep.get(tag);
                        do_IsoDep();
                        break;

                    case 3:
                        log("Mifare Classic not implemented yet.");
                        log("doing nothing now then...");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void addListenerOnButton() {
        bt_send.setOnClickListener( new View.OnClickListener() {
            public void onClick(View view) {
                byte[] data = hex2bytes(et_input.getText().toString());
                if(data.length == 0)
                {
                    log("no data to send...");
                    return;
                }

                switch(spinner_type.getSelectedItemPosition()){
                    case 0:
                        if (tagA != null && tagA.isConnected()){
                            transceive_tagA(data);
                        }
                        else{
                            log("NfcA not connected, waiting...");
                        }
                        break;

                    case 1:
                        if (tagB != null && tagB.isConnected()){
                            transceive_tagB(data);
                        }
                        else{
                            log("NfcB not connected, waiting...");
                        }
                        break;

                    case 2:
                        if (tagISO != null && tagISO.isConnected()){
                            transceive_IsoDep(data);
                        }
                        else{
                            log("IsoDep not connected, waiting...");
                        }
                        break;

                    case 3:
                        log("Mifare Classic is to be implemented ...");
                        break;
                }
            }
        });

        tv_log.setOnLongClickListener(new View.OnLongClickListener() {
            public boolean onLongClick(View v) {
                Toast.makeText(v.getContext(), "Log cleared!", Toast.LENGTH_SHORT).show();
                tv_log.setText("");
                return false;
            }
        });
    }


    public String bytes2hex(byte[] data) {
        StringBuffer result = new StringBuffer();
        for (byte d : data) {
            result.append(String.format("%02X", d & 0xFF));
            result.append(" ");
        }
        return result.toString().trim();
    }

    public byte[] hex2bytes(String data) {
        String _data = data.replace(" ", "");
        byte[] result = new byte[_data.length() / 2];
        for (int i = 0; i+1 < _data.length(); i += 2) {
            try {
                result[i/2] = (byte) Integer.parseInt(_data.substring(i, i + 2), 16);
            }catch (Exception e){
                log(e.toString());
                return new byte[0];
            }
        }
        return result;
    }


    public void log(String s){
        tv_log.append(s + "\n");
        LogScrollDown();
    }

    public void LogScrollDown() {
        int tmp = tv_log.getLayout().getLineTop(tv_log.getLineCount()) - tv_log.getHeight();
        if (tmp > 0) {
            tv_log.scrollTo(0, tmp);
        }
    }
}