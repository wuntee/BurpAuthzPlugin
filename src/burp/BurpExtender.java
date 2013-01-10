package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JMenuItem;

import com.wuntee.burp.authz.AuthzContainer;


public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
	private IBurpExtenderCallbacks burpCallback;
	private AuthzContainer tabContainer;
	
	public static String TAB_TEXT = "Authz";
	public static String MENU_ITEM_TEXT = "Send request(s) to Authz";
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks burpCallback) {
		this.burpCallback = burpCallback;
		this.tabContainer = new AuthzContainer(burpCallback);

		burpCallback.addSuiteTab(this);
		burpCallback.registerContextMenuFactory(this);
	}
		
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IHttpRequestResponse responses[] = invocation.getSelectedMessages();
		
		if(responses.length > 0){
			List<JMenuItem> ret = new LinkedList<JMenuItem>();
			JMenuItem menuItem = new JMenuItem(MENU_ITEM_TEXT);
			menuItem.addActionListener(new ActionListener(){
				@Override
				public void actionPerformed(ActionEvent arg0) {
					if(arg0.getActionCommand().equals(MENU_ITEM_TEXT)){
						tabContainer.addRequests(responses);
					}
				}
			});
			ret.add(menuItem);
			return(ret);
		}
		
		return null;
	}

	@Override
	public String getTabCaption() {
		return(TAB_TEXT);
	}

	@Override
	public Component getUiComponent() {
		return(this.tabContainer);
	}

}
