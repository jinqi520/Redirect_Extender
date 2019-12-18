package burp;

import com.sun.deploy.net.protocol.about.AboutURLConnection;

import javax.swing.*;
import java.awt.*;
import java.sql.BatchUpdateException;

public class BurpExtender implements IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor, ITab, IHttpListener{
    IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;
    public JPanel mainPanel;
    public JPanel leftPanel;
    public JPanel rightPanel;
    public JPanel l_notice;
    public JPanel l_domain;
    public JPanel l_whitedomain;
    public JTextField f_whitedomain;
    public JPanel l_evildomain;
    public JTextField f_evildomain;
    public JScrollPane scrollPane;
    public JTextArea attackStringsTextarea;

    //  当用户没有设置白名单域名 或 payload中不需要使用white doamin时应该直接跳过该条payload
    public static final String White_Domain_Place = "{White_Doamin}";
    public static final String Evil_Domain_Place = "{Evil_Domain}";
    public static final String Version = "v1.0";

    public static final byte[][] PAYLOADS = {
            ("/%09/" + BurpExtender.Evil_Domain_Place).getBytes(),
            ("/%2f%2f" + BurpExtender.Evil_Domain_Place).getBytes()
    };



    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Redirect Extender");
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        callbacks.registerIntruderPayloadProcessor(this);
        SwingUtilities.invokeLater(
                new Runnable() {
                    public void run() {
                        BurpExtender.this.mainPanel = new JPanel(new GridLayout(1,2));
                        BurpExtender.this.leftPanel = new JPanel(new GridLayout(2,1));
                        BurpExtender.this.rightPanel = new JPanel();

                        BurpExtender.this.l_notice = new JPanel(new GridLayout(2,1));
                        BurpExtender.this.l_domain = new JPanel(new GridLayout(2,1));
                        JLabel titleLabel = new JLabel("<html><center><h2>Redirect Extender</h2>Created By: <em>京亟</em> (1352220829@qq.com)<br />\n"
                            + "Version: " + BurpExtender.this.Version + "</center><br />"
                        );

                        String initialText = "<html><center>该插件主要用于检测重定向漏洞，其实重定向漏洞手工检测起来是非常简单的，只需要将可疑参数修改成为指定url即可，但是很多时候" +
                                "后端程序可能会做一些限制，比如使用白名单限制域名，再或者会为传入的参数指定指定前缀进行字符串拼凑，这些都是存在绕过的可能性的。然后绕过的手段无非是使用" +
                                "一些特殊字符进行绕过，手工测试中难免会有遗漏，并且测试十多个payload也是很麻烦的事情。\n 该插件V2.0版本会考虑支持通过fuzz绕过ssrf的白名单校验，道理" +
                                "其实是一样的，只不过判断漏洞存在与否的方法不一样，重定向漏洞的识别只需要判断返回包中的host，而ssrf需要看指定evil_domain的dns记录了</center>";
                        JLabel initialLabel = new JLabel(initialText);
                        BurpExtender.this.l_notice.add(titleLabel);
                        BurpExtender.this.l_notice.add(initialLabel);
                        // 白名单域名输入框
                        BurpExtender.this.l_whitedomain = new JPanel(new GridLayout(1,2));
                        JLabel white_label = new JLabel("白名单域名：");
                        // f_whitedomain中放入的是白名单域名，不填的话就是null
                        BurpExtender.this.f_whitedomain = new JTextField(20);
                        BurpExtender.this.l_whitedomain.add(white_label);
                        BurpExtender.this.l_whitedomain.add(BurpExtender.this.f_whitedomain);
                        // evil域名输入框,默认是www.baidu.com，如果是测试ssrf将起改成dns服务器域名
                        BurpExtender.this.l_evildomain = new JPanel(new GridLayout(2,1));
                        JLabel evil_label = new JLabel("evil 域名：");
                        BurpExtender.this.f_evildomain = new JTextField(20);
                        BurpExtender.this.f_evildomain.setText("www.baidu.com");
                        BurpExtender.this.l_evildomain.add(evil_label);
                        BurpExtender.this.l_evildomain.add(BurpExtender.this.f_evildomain);

                        BurpExtender.this.l_domain.add(BurpExtender.this.l_whitedomain);
                        BurpExtender.this.l_domain.add(BurpExtender.this.l_evildomain);

                        BurpExtender.this.leftPanel.add(BurpExtender.this.l_notice);
                        BurpExtender.this.leftPanel.add(BurpExtender.this.l_domain);

                        // 写右边的UI
                        String payloads = "";
                        for(byte[] bs :BurpExtender.PAYLOADS){
                            payloads += new String(bs) + "\n";
                        }
                        BurpExtender.this.attackStringsTextarea = new JTextArea(30, 50);
                        BurpExtender.this.attackStringsTextarea.setText(payloads);
                        BurpExtender.this.scrollPane = new JScrollPane(
                                BurpExtender.this.attackStringsTextarea,
                                ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS
                        );
                        BurpExtender.this.rightPanel.add(BurpExtender.this.scrollPane);

                        BurpExtender.this.mainPanel.add(BurpExtender.this.leftPanel);
                        BurpExtender.this.mainPanel.add(BurpExtender.this.rightPanel);
                        BurpExtender.this.callbacks.customizeUiComponent(BurpExtender.this.mainPanel);
                        // 将ITab实例加入IBurpExtenderCallbacks
                        BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
                    }
                }
        );
    }


    // implement IIntruderPayloadGeneratorFactory
    public String getGeneratorName() {
        return "Open Redirect Payload";
    }
    // implement IIntruderPayloadGeneratorFactory
    // 返回一个IntruderPayloadGeneratorFactory实例，实现具体的攻击代码
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new Redirect(this);
    }

    // implement IIntruderPayloadProcessor
    // intruder processor 用于处理在使用payload前进行预处理，比说说加上前后缀，或者编码等等
    public String getProcessorName() {
        return "Redirect process rule";
    }

    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        return this.helpers.stringToBytes(this.helpers.urlEncode(this.helpers
                .bytesToString(currentPayload)));
    }


    // implement ITab
    public String getTabCaption() {
        return "Redirect Extender";
    }
    // implement ITab
    public Component getUiComponent() {
        return this.mainPanel;
    }

    // implements IHttpListener
    // 用于处理proxy到的流量
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {


    }

    // 当然也可以让 BurpExtender自己实现这个接口
    class Redirect implements IIntruderPayloadGenerator {
        int payloadindex;
        BurpExtender extenderInstance = null;
        String white_domain ;
        String evil_doamin;
        Boolean w_flag;
        String[] PAYLOADS;
        Redirect(BurpExtender extenderInstance){
            this.extenderInstance = extenderInstance;
            white_domain = extenderInstance.f_whitedomain.getText();
            w_flag = false;
            if(!white_domain.equals("")&&!(white_domain == null)){
                w_flag = true;
            }
            evil_doamin = extenderInstance.f_evildomain.getText();

            String payload = extenderInstance.attackStringsTextarea.getText();
            this.PAYLOADS = payload.split("\n");
        }

        public boolean hasMorePayloads() {
            return false;
        }

        public byte[] getNextPayload(byte[] baseValue) {


            return new byte[0];
        }

        public void reset() {

        }
    }
}
