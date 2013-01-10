package com.wuntee.burp.authz;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class BurpApiHelper {
	public static void sendRequestResponseToRepeater(IBurpExtenderCallbacks callback, IHttpRequestResponse req){
		callback.sendToRepeater(req.getHttpService().getHost(), req.getHttpService().getPort(), req.getHttpService().getProtocol().equalsIgnoreCase("https"), req.getRequest(), null);
	}
	
	public static void sendRequestResponseToIntruder(IBurpExtenderCallbacks callback, IHttpRequestResponse req){
		callback.sendToIntruder(req.getHttpService().getHost(), req.getHttpService().getPort(), req.getHttpService().getProtocol().equalsIgnoreCase("https"), req.getRequest(), null);
	}
}
