package burp;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor, ITab{
    IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;
    public JPanel mainPanel;
    public JPanel leftPanel;
    public JPanel rightPanel;
    public JPanel l_notice;

    //  当用户没有设置白名单域名 或 payload中不需要使用white doamin时应该直接跳过该条payload
    public static final String White_Domain_Place = "{White_Doamin}";
    public static final String Evil_Domain_Place = "{Evil_Domain}";
    public static final String Version = "v1.0";

    public static final byte[][] Payload = {
            ("/%09/" + BurpExtender.Evil_Domain_Place).getBytes(),
            ("/%2f%2f" + BurpExtender.Evil_Domain_Place).getBytes()
    };



    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Redirect Extender");
        SwingUtilities.invokeLater(
                new Runnable() {
                    public void run() {
                        BurpExtender.this.mainPanel = new JPanel(new GridLayout(1,2));
                        BurpExtender.this.leftPanel = new JPanel(new GridLayout(2,1));
                        BurpExtender.this.rightPanel = new JPanel();

                        BurpExtender.this.l_notice = new JPanel();
                        JLabel titleLabel = new JLabel("<html><center><h2>Redirect Extender</h2>Created By: <em>京亟</em> (1352220829@qq.com)<br />\n"
                            + "Version: " + BurpExtender.this.Version + "</center><br />"
                        );

                        String initialText = "<html><center>该插件主要用于检测重定向漏洞，其实重定向漏洞手工检测起来是非常简单的，只需要将可疑参数修改成为指定url即可，但是很多时候" +
                                "后端程序可能会做一些限制，比如使用白名单限制域名，再或者会为传入的参数指定指定前缀进行字符串拼凑，这些都是存在绕过的可能性的。然后绕过的手段无非是使用" +
                                "一些特殊字符进行绕过，手工测试中难免会有遗漏，并且测试十多个payload也是很麻烦的事情。\n 该插件V2.0版本会考虑支持通过fuzz绕过ssrf的白名单校验，道理" +
                                "其实是一样的，只不过判断漏洞存在与否的方法不一样，重定向漏洞的识别只需要判断返回包中的host，而ssrf需要看指定evil_domain的dns记录了</center>";



                        mainPanel.add(leftPanel);
                        mainPanel.add(rightPanel);
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
        return new Redirect();
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

    // 当然也可以让 BurpExtender自己实现这个接口
    class Redirect implements IIntruderPayloadGenerator {

        Redirect(){

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
