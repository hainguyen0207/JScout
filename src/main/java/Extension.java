import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;


public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JScout");

        APITab apiTab = new APITab(api);
        MyHttpHandler myHandler = new MyHttpHandler(api, apiTab);

        apiTab.setMyHttpHandler(myHandler);

        api.userInterface().registerSuiteTab("JScout", apiTab.getComponent());
        api.http().registerHttpHandler(myHandler);
        api.extension().registerUnloadingHandler(apiTab::saveData);
    }
}

