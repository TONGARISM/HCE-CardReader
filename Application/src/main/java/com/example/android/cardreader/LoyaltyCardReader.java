/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.android.cardreader;

import android.content.Context;
import android.database.Cursor;
import android.graphics.Point;
import android.media.MediaPlayer;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.content.ContentValues;

import com.example.android.common.logger.Log;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import android.os.Handler;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.util.Random;

/**
 * Callback class, invoked when an NFC card is scanned while the device is running in reader mode.
 *
 * Reader mode can be invoked by calling NfcAdapter
 */
public class LoyaltyCardReader implements NfcAdapter.ReaderCallback {
    private static final String TAG = "LoyaltyCardReader";
    // AID for our loyalty card service.
    private static final String SAMPLE_LOYALTY_CARD_AID = "F222222222";
    // ISO-DEP command HEADER for selecting an AID.
    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String SELECT_APDU_HEADER = "00A40400";
    // "OK" status word sent in response to SELECT AID command (0x9000)
    private static final byte[] SELECT_OK_SW = {(byte) 0x90, (byte) 0x00};

    // ISO-DEP command HEADER for selecting an AID.
    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String INT_AUTH_HEADER = "00880000";

    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String READ_BIN_HEADER = "00B00000";

    private static final String WRITE_BIN_HEADER = "00D00000";

    private static final String INT_AUTH_KEY ="7788";

    private static final int READ_BINARY_SIZE = 5;
    private static final int WRITE_BINARY_SIZE = 12;

    private static final String WRITE_TOKEN = "AA";
    private static final String WRITE_POINT = "BB";

    private PointDB mPointDB;

    // Weak reference to prevent retain loop. mAccountCallback is responsible for exiting
    // foreground mode before it becomes invalid (e.g. during onPause() or onStop()).
    private WeakReference<AccountCallback> mAccountCallback;

    private MediaPlayer mMp;

    private Context mContext;

    private final Handler handler = new Handler();

    private final Runnable delayFunc= new Runnable() {
        @Override
        public void run() {
            mMp.start();
        }
    };

    public interface AccountCallback {
        public void onAccountReceived(String account, int type);
    }

    public LoyaltyCardReader(AccountCallback accountCallback, Context context) {
        mAccountCallback = new WeakReference<AccountCallback>(accountCallback);
        mContext = context;
    }

    public void createPointDB() {
        mPointDB = new PointDB(mContext);
    }

    /**
     * Callback when a new tag is discovered by the system.
     *
     * <p>Communication with the card should take place here.
     *
     * @param tag Discovered tag
     */
    @Override
    public void onTagDiscovered(Tag tag) {
        String receiveNumber = null;

        Log.i(TAG, "New tag discovered");
        // Android's Host-based Card Emulation (HCE) feature implements the ISO-DEP (ISO 14443-4)
        // protocol.
        //
        // In order to communicate with a device using HCE, the discovered tag should be processed
        // using the IsoDep class.
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep != null) {
            try {
                // Connect to the remote NFC device
                isoDep.connect();
                //---------------1st seq start---------------
                // Build SELECT AID command for our loyalty card service.
                // This command tells the remote device which service we wish to communicate with.
                Log.i(TAG, "Requesting remote AID: " + SAMPLE_LOYALTY_CARD_AID);
                byte[] command = BuildSelectApdu(SAMPLE_LOYALTY_CARD_AID);
                // Send command to remote device
                Log.i(TAG, "Sending: " + ByteArrayToHexString(command));
                byte[] result = isoDep.transceive(command);
                // If AID is successfully selected, 0x9000 is returned as the status word (last 2
                // bytes of the result) by convention. Everything before the status word is
                // optional payload, which is used here to hold the account number.
                int resultLength = result.length;
                byte[] statusWord = {result[resultLength-2], result[resultLength-1]};
                byte[] payload = Arrays.copyOf(result, resultLength-2);
                if (Arrays.equals(SELECT_OK_SW, statusWord)) {
                    //accountNumber = new String(payload, "UTF-8");
                    receiveNumber = ByteArrayToHexString(payload);
                    Log.i(TAG, "Received TOKEN: " + receiveNumber);
                    Log.i(TAG, "SelectApdu Received: SELECT_OK_SW");

                    //tokenがDB存在するか、検索
                    Cursor cursor = mPointDB.query(PointDB.TABLE_TITLE, null, PointDB.COLUMN_TOKEN+"=?", new String[]{receiveNumber});

                    //DBに存在する(既に登録済みユーザであれば、ポイント更新)
                    if(cursor.moveToFirst()) {
                        Log.d(TAG, "known Account!!!");
                        //ポイント10加算
                        String point = cursor.getString(cursor.getColumnIndex(PointDB.COKUMN_POINT));
                        point = String.valueOf(Integer.parseInt(point) + 10);
                        String sendPoint = String.valueOf(String.format("%1$012d", Integer.parseInt(point)));

                        //データベース更新
                        ContentValues values = new ContentValues();
                        values.put(PointDB.COKUMN_POINT, sendPoint);
                        mPointDB.update(PointDB.TABLE_TITLE, values, PointDB.COLUMN_TOKEN+" = ?", new String[]{receiveNumber});
                        values.clear();
                        //ポイント残高送信
                        byte[] command_bin = BuildWriteBinaryAdpu(WRITE_BINARY_SIZE, point, WRITE_POINT);
                        Log.i(TAG, "Sending: " + ByteArrayToHexString(command_bin));
                        byte[] result_bin = isoDep.transceive(command_bin);
                        Log.i(TAG, "Write Binary Received:" +ByteArrayToHexString(result_bin));
                        int resultLength_bin = result_bin.length;
                        byte[] statusWord_bin = {result_bin[resultLength_bin-2], result_bin[resultLength_bin-1]};
                        if (Arrays.equals(SELECT_OK_SW, statusWord_bin)) {
                            //ポイント残高表示＋効果音
                            mAccountCallback.get().onAccountReceived("Point : "+point, 2);
                            mMp = MediaPlayer.create(mContext, R.raw.tongaroidpay);
                            handler.postDelayed(delayFunc, 150);
                        }
                        return;

                    }
                } else {
                    Log.e(TAG, "SelectApdu Received: UNKNOWN");
                    return;
                }

                //---------------2nd seq start.---------------
                //登録シーケンス
                byte[] command_auth = BuildIntAuthApdu(INT_AUTH_KEY);
                Log.i(TAG, "Sending: " + ByteArrayToHexString(command_auth));
                byte[] result_auth = isoDep.transceive(command_auth);
                Log.i(TAG, "INT Auth Seq Received:" +ByteArrayToHexString(result_auth));
                int resultLength_auth = result_auth.length;
                byte[] statusWord_auth = {result_auth[resultLength_auth-2], result_auth[resultLength_auth-1]};
                byte[] payload2 = Arrays.copyOf(result_auth, resultLength_auth - 2);
                String token ="";

                String hash = ByteArrayToHexString(payload2);
                Log.i(TAG, "INT Auth Seq Received: payload:" + hash);

                if (Arrays.equals(SELECT_OK_SW, statusWord_auth)) {
                    //トークン生成
                    token = createToken(hash);
                }

                //---------------3rd seq start.---------------
                byte[] command_bin = BuildWriteBinaryAdpu(WRITE_BINARY_SIZE, token, WRITE_TOKEN);
                Log.i(TAG, "Sending: " + ByteArrayToHexString(command_bin));
                byte[] result_bin = isoDep.transceive(command_bin);
                Log.i(TAG, "Write Binary Received:" +ByteArrayToHexString(result_bin));
                int resultLength_bin = result_bin.length;
                byte[] statusWord_bin = {result_bin[resultLength_bin-2], result_bin[resultLength_bin-1]};
                if (Arrays.equals(SELECT_OK_SW, statusWord_bin)) {
                    Log.i(TAG, "Write Binary Received: SELECT_OK_SW");
                    ContentValues values = new ContentValues();
                    values.put(PointDB.COLUMM_HASH, hash);
                    values.put(PointDB.COLUMN_TOKEN, token);
                    values.put(PointDB.COKUMN_POINT, "10");
                    mPointDB.insert(values);
                    values.clear();
                }
                //登録完了表示+効果音
                mAccountCallback.get().onAccountReceived("Completed.", 1);
                mMp = MediaPlayer.create(mContext, R.raw.touroku);
                handler.postDelayed(delayFunc, 150);

            } catch (IOException e) {
                Log.e(TAG, "Error communicating with card: " + e.toString());
            }
        }
    }

    /**
     * Build APDU for SELECT AID command. This command indicates which service a reader is
     * interested in communicating with. See ISO 7816-4.
     *
     * @param aid Application ID (AID) to select
     * @return APDU for SELECT AID command
     */
    public static byte[] BuildSelectApdu(String aid) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return HexStringToByteArray(SELECT_APDU_HEADER + String.format("%02X", aid.length() / 2) + aid);
    }

    public static byte[] BuildIntAuthApdu(String key) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | Lc field | DATA | Le field]
        //see http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx#chap6_13
        return HexStringToByteArray(INT_AUTH_HEADER + String.format("%02X", key.length() / 2) + key + "05");
    }

    public static byte[] BuildReadBinaryApdu(int len) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | Lc field | DATA | Le field]
        //see http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx#chap6_1
        return HexStringToByteArray(READ_BIN_HEADER + "00" + "00" + String.format("%02X", len));
    }

    public static byte[] BuildWriteBinaryAdpu(int len, String token, String type) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | Lc field | DATA | Le field]
        //see http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx#chap6_1
        //return HexStringToByteArray(WRITE_BIN_HEADER + type + String.format("%02X", len/2) + token);
        return HexStringToByteArray(WRITE_BIN_HEADER + type + token);
    }

    static byte[] calcHmac(String key, String str){
        String ALGORISM = "hmacSHA256";
        //String key = "key";
        //String str ="012345";
        byte[] result =null;

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORISM);
        try {
            Mac mac = Mac.getInstance(ALGORISM);
            mac.init(secretKeySpec);
            result = mac.doFinal(str.getBytes());
            Log.i(TAG, "HMAC:"+str + " "+ALGORISM+ " -> " + ByteArrayToHexString(result));

        }
        catch (NoSuchAlgorithmException e) {
            Log.i(TAG, "HMAC:NoSuchAlgorithmException:" + ALGORISM);
        }
        catch (InvalidKeyException e) {
            Log.i(TAG, "HMAC:InvalidKeyException:" + key);
        }

        return result;
    }
    /**
     * Utility class to convert a byte array to a hexadecimal string.
     *
     * @param bytes Bytes to convert
     * @return String, containing hexadecimal representation.
     */
    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for ( int j = 0; j < bytes.length; j++ ) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Utility class to convert a hexadecimal string to a byte string.
     *
     * <p>Behavior with input strings containing non-hexadecimal characters is undefined.
     *
     * @param s String containing hexadecimal characters to convert
     * @return Byte array generated from input
     */
    public static byte[] HexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**トークン生成関数**/
    private String createToken(String hash_org) {
        int token;
        String hash_ini, hash_end, hash_token;
        int randLength = 6;

        //先頭と末尾の3文字を除いた中間の数字をトークンに置き換える
        hash_ini = hash_org.substring(0,3);
        hash_end = hash_org.substring(hash_org.length()-3);
        hash_token = hash_org.substring(3,hash_org.length()-3);
        Log.d(TAG, hash_org + "\n" + hash_ini + "\n" + hash_end);


        String strRand = new String();
        Random rnd = new Random();
        for(int i=0; i<randLength; i++){
            strRand += String.valueOf(rnd.nextInt(10));
        }
        Log.d(TAG, hash_ini+strRand+hash_end);

        return hash_ini+strRand+hash_end;
    }

}
