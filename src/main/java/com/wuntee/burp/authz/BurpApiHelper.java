package com.wuntee.burp.authz;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;

public class BurpApiHelper {
	public static void sendRequestResponseToRepeater(IBurpExtenderCallbacks callback, IHttpRequestResponse req){
		callback.sendToRepeater(req.getHttpService().getHost(), req.getHttpService().getPort(), req.getHttpService().getProtocol().equalsIgnoreCase("https"), req.getRequest(), null);
	}
	
	public static void sendRequestResponseToIntruder(IBurpExtenderCallbacks callback, IHttpRequestResponse req){
		callback.sendToIntruder(req.getHttpService().getHost(), req.getHttpService().getPort(), req.getHttpService().getProtocol().equalsIgnoreCase("https"), req.getRequest(), null);
	}
	
	public static String iParameterTypeToString(IParameter param){
		String type = "";
		switch(param.getType()){
		case IParameter.PARAM_BODY:
			type = "Body";
			break;
		case IParameter.PARAM_COOKIE:
			type = "Cookie";
			break;
		case IParameter.PARAM_JSON:
			type = "JSON";
			break;
		case IParameter.PARAM_MULTIPART_ATTR:
			type = "Mutlipart";
			break;
		case IParameter.PARAM_URL:
			type = "URL";
			break;
		case IParameter.PARAM_XML:
			type = "XML";
			break;
		case IParameter.PARAM_XML_ATTR:
			type = "XML-Attr";
			break;
		default:
			type = "Unknown";
		}
		return(type);
	}
}
