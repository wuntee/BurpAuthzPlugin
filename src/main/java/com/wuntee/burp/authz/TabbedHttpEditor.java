package com.wuntee.burp.authz;

import java.awt.Component;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

public class TabbedHttpEditor extends Container {

	private static final long serialVersionUID = 1L;

	private IBurpExtenderCallbacks burpCallback;
	private BurpTextEditorWithData textEditor;
	
	private DefaultTableModel paramsTableModel;
	private String[] PARAMS_HEADERS = {"Type", "Name", "Value"};
	private DefaultTableModel headersTableModel;
	private String[] HEADERS_HEADERS = {"Name", "Value"};
	
	private IHttpRequestResponse requestResponse;
	
	public TabbedHttpEditor(IBurpExtenderCallbacks burpCallback){
		this.burpCallback = burpCallback;
		
		textEditor = new BurpTextEditorWithData(burpCallback);
		
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0};
		gridBagLayout.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 0;
		gbc_tabbedPane.gridy = 0;
		add(tabbedPane, gbc_tabbedPane);
		
		addRightClickActions(textEditor.getComponent());
		tabbedPane.addTab("Raw", null, new JScrollPane(textEditor.getComponent()), null);
		
		paramsTableModel = new DefaultTableModel(null, PARAMS_HEADERS);
		JTable table = new JTable(paramsTableModel);
		JScrollPane scrollPane_1 = new JScrollPane(table);
		addRightClickActions(table);
		table.setAutoCreateRowSorter(true);
		tabbedPane.addTab("Params", null,scrollPane_1, null);
		
		headersTableModel = new DefaultTableModel(null, HEADERS_HEADERS);
		JTable table2 = new JTable(headersTableModel);
		JScrollPane scrollPane_2 = new JScrollPane(table2);
		addRightClickActions(table2);
		table2.setAutoCreateRowSorter(true);
		tabbedPane.addTab("Headers", null, scrollPane_2, null);
	}
	
	public void loadRequest(IHttpRequestResponse request){
		this.requestResponse = request;
		
		IRequestInfo req = burpCallback.getHelpers().analyzeRequest(request);
		
		loadData(request.getRequest(), req.getParameters(), req.getHeaders());
	}
	
	private void loadData(byte[] data, List<IParameter> params, List<String> headers){
		textEditor.setText(data);
		
		paramsTableModel.getDataVector().removeAllElements();
		for(IParameter param : params){
			String type;
			try {
				type = new String(new byte[]{param.getType()},"UTF-8");
			} catch (UnsupportedEncodingException e) {
				type = "";
			}
			
			paramsTableModel.addRow(new String[]{type, param.getName(), param.getValue()});
		}
		
		headersTableModel.getDataVector().removeAllElements();
		for(String header : headers){
			String h[] = header.split(":", 2);
			String key = (h[0] != null) ? h[0].trim() : "";
			String val = (h[1] != null) ? h[1].trim() : "";
			headersTableModel.addRow(new String[]{key, val});
		}
	}
	
	public void clearData(){
		this.requestResponse = null;
		paramsTableModel.getDataVector().removeAllElements();
		headersTableModel.getDataVector().removeAllElements();
		textEditor.setText(new byte[]{});
	}
	
	public BurpTextEditorWithData getTextEditor(){
		return(this.textEditor);
	}

	private static void addPopup(Component component, final JPopupMenu popup) {
		component.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showMenu(e);
				}
			}
			public void mouseReleased(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showMenu(e);
				}
			}
			private void showMenu(MouseEvent e) {
				popup.show(e.getComponent(), e.getX(), e.getY());
			}
		});
	}
	
	private void addRightClickActions(Component comp){
		JPopupMenu popupMenu = new JPopupMenu();
		
		JMenuItem mntmSendToRepeater = new JMenuItem("Send to repeater");
		mntmSendToRepeater.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
		    	   IHttpRequestResponse req = requestResponse;
		    	   if(req != null){
		    		   BurpApiHelper.sendRequestResponseToRepeater(burpCallback, req);
		    	   }				
			}
		});
		popupMenu.add(mntmSendToRepeater);
		JMenuItem mntmSendToIntruder = new JMenuItem("Send to intruder");
		mntmSendToIntruder.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
		    	   IHttpRequestResponse req = requestResponse;
		    	   if(req != null){
		    		   BurpApiHelper.sendRequestResponseToIntruder(burpCallback, req);
		    	   }				
			}
		});
		popupMenu.add(mntmSendToIntruder);
		addPopup(comp, popupMenu);
	}

}
