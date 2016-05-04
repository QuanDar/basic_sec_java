package basic_security.beste_groep.view;

import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;

import javax.swing.ButtonGroup;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.File;
import java.net.URL;

import javax.swing.JRadioButton;
import javax.swing.JLabel;


import javax.swing.ImageIcon;

import basic_security.beste_groep.controller.Controller;

import java.awt.SystemColor;


public class TCPClient {
	
	private Controller con;
	private FileTree tree;
	
	private JFrame frame;
	private JTextPane log;
	private JRadioButton rdbtnGenerateAes;
	private JRadioButton rdbtnGenerateDes;
	private JButton btnGenerateKeys;
	private JButton browseButton;
	private JButton encryptButton;
	private JButton sendButton;
	private JLabel browseLabel;
	private JLabel imageLabel;
	
	private ButtonGroup grp;
	private JFileChooser fileChooser;
	private File file;
	
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					TCPClient window = new TCPClient();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	public TCPClient() {
		initialize();
		con = new Controller(log);
		
		JLabel lblNewLabel_1 = new JLabel("");
		lblNewLabel_1.setBounds(384, 11, 200, 381);
		frame.getContentPane().add(lblNewLabel_1);
	}

	private void initialize() {
		frame = new JFrame();
		frame.setResizable(false);
		frame.getContentPane().setBackground(SystemColor.inactiveCaption);
		frame.setBackground(SystemColor.activeCaption);
		frame.setTitle("TCP Client");
		frame.setBounds(100, 100, 650, 431);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		
		log = new JTextPane();
		log.setText("Welcome!" + "\n");
		log.setForeground(Color.GREEN);
		log.setBackground(Color.BLACK);
		log.setFont(new Font("Consolas", 1, 14));
		JScrollPane scrollPane = new JScrollPane(log);
		scrollPane.setBounds(10, 277, 364, 115);
		frame.getContentPane().add(scrollPane);
		
		rdbtnGenerateAes = new JRadioButton("AES");
		rdbtnGenerateAes.setBackground(SystemColor.inactiveCaption);
		rdbtnGenerateAes.setForeground(Color.BLACK);
		rdbtnGenerateAes.setSelected(true);
		rdbtnGenerateAes.setBounds(10, 32, 120, 23);
		rdbtnGenerateAes.setActionCommand("AES");
		frame.getContentPane().add(rdbtnGenerateAes);
		
		rdbtnGenerateDes = new JRadioButton("DES");
		rdbtnGenerateDes.setBackground(SystemColor.inactiveCaption);
		rdbtnGenerateDes.setForeground(Color.BLACK);
		rdbtnGenerateDes.setBounds(10, 58, 120, 23);
		rdbtnGenerateDes.setActionCommand("DES");
		frame.getContentPane().add(rdbtnGenerateDes);
		
		grp = new ButtonGroup();
		grp.add(rdbtnGenerateAes);
		grp.add(rdbtnGenerateDes);
		
		JLabel lblNewLabel = new JLabel("Choose the encryption technique for the symmetric key:");
		lblNewLabel.setBounds(10, 11, 338, 14);
		frame.getContentPane().add(lblNewLabel);
		
		JLabel lblLog = new JLabel("Log:");
		lblLog.setBounds(10, 252, 46, 14);
		frame.getContentPane().add(lblLog);
		
		imageLabel = new JLabel("");
		imageLabel.setBounds(140, 32, 234, 234);
		URL url = TCPClient.class.getResource("/resources/lock.png");
		ImageIcon icon = new ImageIcon(url);
		imageLabel.setIcon(icon);
		frame.getContentPane().add(imageLabel);
		
		tree = new FileTree(new File("."));
		tree.setBounds(384, 11, 250, 381);
		frame.getContentPane().add(tree);
		appendButtons();
		
		browseLabel = new JLabel("");
		browseLabel.setBounds(10, 227, 120, 14);
		frame.getContentPane().add(browseLabel);
	}
	
	private void appendButtons() {
		btnGenerateKeys = new JButton("Generate keys");
		btnGenerateKeys.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				generateKeysButtonAction(arg0);
			}
		});
		btnGenerateKeys.setBounds(10, 88, 120, 23);
		frame.getContentPane().add(btnGenerateKeys);
		
		browseButton = new JButton("Browse...");
		browseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				file = null;
				fileChooser = new JFileChooser();
				while(file == null) {
					fileChooser.showOpenDialog(null);
					file = fileChooser.getSelectedFile();
				}
				browseLabel.setText(file.getName());
				con.updateLog("Selected file: " + file.getAbsolutePath());
				encryptButton.setEnabled(true);
				sendButton.setEnabled(false);
			}
		});
		browseButton.setEnabled(false);
		browseButton.setBounds(10, 122, 120, 23);
		frame.getContentPane().add(browseButton);
		
		encryptButton = new JButton("Encrypt file");
		encryptButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				encryptFileButtonAction(arg0);
			}
		});
		encryptButton.setEnabled(false);
		encryptButton.setBounds(10, 156, 120, 23);
		frame.getContentPane().add(encryptButton);
		
		sendButton = new JButton("Send file");
		sendButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				con.sendFile();
			}
		});
		sendButton.setEnabled(false);
		sendButton.setBounds(10, 190, 120, 23);
		frame.getContentPane().add(sendButton);
	}
	
	public void generateKeysButtonAction(ActionEvent arg0) {
		con.generateSymmetricKey(grp.getSelection().getActionCommand());
		con.generateRSAKeys();
		browseButton.setEnabled(true);
		browseLabel.setText("No file selected.");
		encryptButton.setEnabled(false);
		sendButton.setEnabled(false);
	}
	
	public void encryptFileButtonAction(ActionEvent arg0) {
		con.encryptFile(file);
		con.encryptSymmetricKey();
		con.hashOriginalFile();
		con.encryptHash();
		sendButton.setEnabled(true);
	}
}
