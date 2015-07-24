package com.rjfun.cordova.plugin;

import java.lang.reflect.Method;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.PluginResult.Status;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Context;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.WifiLock;
import android.util.Log;

public class WifiAdmin extends CordovaPlugin { 
	
	private static final String LOGTAG = "WifiAdmin";
	
    /** Cordova Actions. */
    private static final String ACTION_GET_WIFI_INFO = "getWifiInfo";
    private static final String ACTION_ENABLE_WIFI = "enableWifi";
    private static final String ACTION_CONNECT_WIFI = "connectWifi";
    private static final String ACTION_ENABLE_WIFI_AP = "enableWifiAP";
    private static final String ACTION_ENABLE_WIFI_LOCK = "enableWifiLock";
    
    private WifiLock wifiLock = null;

    @Override
    public boolean execute(String action, JSONArray inputs, CallbackContext callbackContext) throws JSONException {
        PluginResult result = null;
        if (ACTION_GET_WIFI_INFO.equals(action)) {
            result = executeGetWifiInfo(inputs, callbackContext);
            
        } else if (ACTION_ENABLE_WIFI.equals(action)) {
            result = executeEnableWifi(inputs, callbackContext);
            
        } else if (ACTION_CONNECT_WIFI.equals(action)) {
            result = executeConnectWifi(inputs, callbackContext);
            
        } else if (ACTION_ENABLE_WIFI_AP.equals(action)) {
            result = executeEnableWifiAP(inputs, callbackContext);
            
        } else if (ACTION_ENABLE_WIFI_LOCK.equals(action)) {
            result = executeEnableWifiLock(inputs, callbackContext);
            
        } else {
            Log.d(LOGTAG, String.format("Invalid action passed: %s", action));
            result = new PluginResult(Status.INVALID_ACTION);
        }
        
        if(result != null) callbackContext.sendPluginResult( result );
        
        return true;
    }
    
    private PluginResult executeGetWifiInfo(JSONArray inputs, CallbackContext callbackContext) {
    	Log.w(LOGTAG, "executeGetWifiInfo");
    	
		Context context = cordova.getActivity().getApplicationContext();
		WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
		WifiInfo wifiInfo = wifiManager.getConnectionInfo();

		JSONObject obj = new JSONObject();
		try {
			JSONObject activity = new JSONObject();
			activity.put("BSSID", wifiInfo.getBSSID());
			activity.put("HiddenSSID", wifiInfo.getHiddenSSID());
			activity.put("SSID", wifiInfo.getSSID());
			activity.put("MacAddress", wifiInfo.getMacAddress());
			activity.put("IpAddress", wifiInfo.getIpAddress());
			activity.put("NetworkId", wifiInfo.getNetworkId());
			activity.put("RSSI", wifiInfo.getRssi());
			activity.put("LinkSpeed", wifiInfo.getLinkSpeed());
			obj.put("activity", activity); 

			JSONArray available = new JSONArray();
	        for (ScanResult scanResult : wifiManager.getScanResults()) {
	        	JSONObject ap = new JSONObject();
	        	ap.put("BSSID", scanResult.BSSID);
	        	ap.put("SSID", scanResult.SSID);
	        	ap.put("frequency", scanResult.frequency);
	        	ap.put("level", scanResult.level);
	        	//netwrok.put("timestamp", String.valueOf(scanResult.timestamp));
	        	ap.put("capabilities", scanResult.capabilities);
	        	available.put(ap);
	        }
	        obj.put("available", available); 


		} catch (JSONException e) {
			e.printStackTrace();
			callbackContext.error("JSON Exception");
		}
		callbackContext.success(obj);

    	return null;
    }

    private PluginResult executeEnableWifi(JSONArray inputs, CallbackContext callbackContext) {
    	Log.w(LOGTAG, "executeEnableWifi");

		Context context = cordova.getActivity().getApplicationContext();
		WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);

		boolean toEnable = true;
		try {
			toEnable = inputs.getBoolean( 0 );
		} catch (JSONException e) {
		      Log.w(LOGTAG, String.format("Got JSON Exception: %s", e.getMessage()));
		      return new PluginResult(Status.JSON_EXCEPTION);
		}
        
		wifiManager.setWifiEnabled( toEnable );
		callbackContext.success();
		
    	return null;
    }

    private PluginResult executeConnectWifi(JSONArray inputs, CallbackContext callbackContext) {
    	Log.w(LOGTAG, "executeConnectWifi");

		boolean toEnable = true;
		try {
			toEnable = inputs.getBoolean( 0 );
		} catch (JSONException e) {
		      Log.w(LOGTAG, String.format("Got JSON Exception: %s", e.getMessage()));
		      return new PluginResult(Status.JSON_EXCEPTION);
		}

		return null;
    }
    /**
     * 创建一个wifi信息
     * @param ssid 名称
     * @param passawrd 密码
     * @param paramInt 有3个参数，1是无密码，2是简单密码，3是wap加密
     * @return
     */
    public WifiConfiguration createWifiAPInfo(boolean enabled,String ssid, String password) {
        //配置网络信息类
        WifiConfiguration localWifiConfiguration1 = new WifiConfiguration();
        //设置配置网络属性
        localWifiConfiguration1.allowedAuthAlgorithms.clear();
        localWifiConfiguration1.allowedGroupCiphers.clear();
        localWifiConfiguration1.allowedKeyManagement.clear();
        localWifiConfiguration1.allowedPairwiseCiphers.clear();
        localWifiConfiguration1.allowedProtocols.clear();

        localWifiConfiguration1.SSID = ssid;
        localWifiConfiguration1.allowedAuthAlgorithms.set(1);
        localWifiConfiguration1.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        localWifiConfiguration1.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        localWifiConfiguration1.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
        localWifiConfiguration1.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        localWifiConfiguration1.allowedKeyManagement.set(0);
        localWifiConfiguration1.wepTxKeyIndex = 0;
        if (password==null || password=="") {  //没有密码
            localWifiConfiguration1.wepKeys[0] = "";
            localWifiConfiguration1.allowedKeyManagement.set(0);
            localWifiConfiguration1.wepTxKeyIndex = 0;
        } else{//wap加密
            localWifiConfiguration1.preSharedKey = password;
            localWifiConfiguration1.allowedAuthAlgorithms.set(0);
            localWifiConfiguration1.allowedProtocols.set(1);
            localWifiConfiguration1.allowedProtocols.set(0);
            localWifiConfiguration1.allowedKeyManagement.set(1);
            localWifiConfiguration1.allowedPairwiseCiphers.set(2);
            localWifiConfiguration1.allowedPairwiseCiphers.set(1);
        }
        return localWifiConfiguration1;
    }
    /**
     * 根据wifi信息创建或关闭一个热点
     * @param paramWifiConfiguration
     * @param paramBoolean 关闭标志
     */
    public void createWifiAP(boolean paramBoolean,String ssid,String password) {
        try {
        	WifiConfiguration paramWifiConfiguration = createWifiAPInfo(paramBoolean,ssid,password);
        	
    		Context context = cordova.getActivity().getApplicationContext();
    		WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            Class localClass = wifiManager.getClass();
            Class[] arrayOfClass = new Class[2];
            arrayOfClass[0] = WifiConfiguration.class;
            arrayOfClass[1] = Boolean.TYPE;
            Method localMethod = localClass.getMethod("setWifiApEnabled",arrayOfClass);
            WifiManager localWifiManager = wifiManager;
            Object[] arrayOfObject = new Object[2];
            arrayOfObject[0] = paramWifiConfiguration;
            arrayOfObject[1] = Boolean.valueOf(paramBoolean);
            localMethod.invoke(localWifiManager, arrayOfObject);
            return;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private PluginResult executeEnableWifiAP(JSONArray inputs, CallbackContext callbackContext) {
    	Log.w(LOGTAG, "executeEnableWifiAP");

		boolean toEnable = true;
		try {
			toEnable = inputs.getBoolean( 0 );
			JSONObject jsobj = inputs.getJSONObject(1);
			String ssid = jsobj.getString("ssid");
			String password = jsobj.getString("password");
	    	Log.w(LOGTAG, "ssid: "+ssid+" password: "+password);
	    	createWifiAP(toEnable,ssid,password);
		} catch (JSONException e) {
		      Log.w(LOGTAG, String.format("Got JSON Exception: %s", e.getMessage()));
		      return new PluginResult(Status.JSON_EXCEPTION);
		}

		return new PluginResult(Status.OK);
    }

    private PluginResult executeEnableWifiLock(JSONArray inputs, CallbackContext callbackContext) {
    	Log.w(LOGTAG, "executeEnableWifiLock");

		boolean toEnable = true;
		try {
			toEnable = inputs.getBoolean( 0 );
		} catch (JSONException e) {
		      Log.w(LOGTAG, String.format("Got JSON Exception: %s", e.getMessage()));
		      return new PluginResult(Status.JSON_EXCEPTION);
		}
		
		Context context = cordova.getActivity().getApplicationContext();
		WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);

		if(wifiLock == null) {
			wifiLock = wifiManager.createWifiLock("Test");
		}
		
		if(wifiLock != null) {
			if(toEnable) {
				wifiLock.acquire();
			} else {
		        if(wifiLock.isHeld()) {
		        	wifiLock.release();
		        }
			}
		}
		
		callbackContext.success();

    	return null;
    }
}