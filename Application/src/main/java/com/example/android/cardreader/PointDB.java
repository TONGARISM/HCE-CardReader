package com.example.android.cardreader;


import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.content.ContentValues;
import android.database.sqlite.SQLiteQueryBuilder;
import android.text.TextUtils;
import android.util.Log;

public class PointDB{

    private SQLiteDatabase mSQLiteDatabase;

    public final static String DB_NAME = "pointdb.db";

    //Title
    public final static String TABLE_TITLE = "title";
    public final static String COLUMM_HASH = "hash";
    public final static String COLUMN_TOKEN = "token";
    public final static String COKUMN_POINT = "point";



    public PointDB(Context context) {
        DatabaseHelper dbHelper = new DatabaseHelper(context);
        mSQLiteDatabase = dbHelper.getWritableDatabase();
    }

    public class DatabaseHelper extends SQLiteOpenHelper {
        private final static int DATABASE_VERSION = 1;

        public DatabaseHelper(Context context) {
            super(context, DB_NAME, null, DATABASE_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE " + TABLE_TITLE + "(" +
                    "_id INTEGER PRIMARY KEY," +
                    COLUMM_HASH + " TEXT," +
                    COLUMN_TOKEN + " TEXT," +
                    COKUMN_POINT + " TEXT" +
                    ")");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {

        }
    }

    public synchronized Cursor query(String table, String[] projection, String selection, String[] selectionArgs) {
        Cursor c = null;
        if (mSQLiteDatabase != null) {
            c = mSQLiteDatabase.query(table, projection, selection, selectionArgs, null, null, null);
            //c = mSQLiteDatabase.rawQuery("SELECT * FROM title WHERE token=?", selectionArgs);
        }
        return c;
    }
    public synchronized long insert(ContentValues values) {
        long rowID = -1;
        if (mSQLiteDatabase != null) {
            rowID = mSQLiteDatabase.insert(TABLE_TITLE, "", values);
        }
        return rowID;
    }
    public synchronized int update(String table, ContentValues values, String selection, String[] selectionArgs) {
        int count = 0;
        if (mSQLiteDatabase != null) {
            count = mSQLiteDatabase.update(table, values,
                    (!TextUtils.isEmpty(selection) ?  selection : ""),
                    selectionArgs);
        }
        return count;
    }
    public synchronized void delete(String table, long id) {
        if (mSQLiteDatabase != null) {
            mSQLiteDatabase.delete(table, "_id = ?", new String[]{String.valueOf(id)});
        }
    }

}