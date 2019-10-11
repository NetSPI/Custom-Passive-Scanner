package burp;

import customPassiveScanner.*;

import java.io.PrintWriter;
import java.lang.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Custom Passive Scanner");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

        // init logger
        Logger.init(new PrintWriter(callbacks.getStdout(), true));

        // initialize collection store
        IssueCollectionStore.init(callbacks);

        CustomScannerTab customScannerTab = new CustomScannerTab(callbacks);
    }
    
    // helper method to search a response for occurrences of a target regex
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, String regex)
    {
        List<int[]> matches = new ArrayList<int[]>();

        String myresponse = helpers.bytesToString(response);
        Matcher matcher = Pattern.compile(regex).matcher(myresponse);

        while (matcher.find()) {
            matches.add(new int[] {matcher.start(), matcher.end()});
        }

        return matches;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        List<IScanIssue> issues = new ArrayList<>(1);

        // check for custom issues in each collection
        for (IssueCollection collection : IssueCollectionStore.getCollections()) {
            if (collection.isInUse()) {

                // iterate over all defined issues
                Iterator it = collection.getIssues().entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry<String, Issue> pair = (Map.Entry) it.next();
                    String issueName = pair.getKey();
                    Issue issue = pair.getValue();

                    // do the bulk of our work
                    List<int[]> matches = getMatches(baseRequestResponse.getResponse(), issue.getRegex());
                    if (matches.size() > 0) {
                        // report the issue
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
                                issueName,
                                issue.getDetail(),
                                issue.getRemediation(),
                                issue.getSeverity()));
                    }
                }
            }
        }

        if (issues.size() > 0) {
            return issues;
        } else {
            return null;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String remediationDetail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String remediationDetail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.remediationDetail = remediationDetail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
		return "None.";
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
		return remediationDetail;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}