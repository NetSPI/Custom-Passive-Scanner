package customPassiveScanner;

import java.util.Iterator;
import java.util.Map;

public class Issue {
    private String name;
    private String detail;
    private String remediation;
    private String severity;
    private String regex;

    public Issue() {
    }

    public static Issue createIssue(String name, Map<String, String> issueMap) {
        Logger.log("Creating issue: " + name);
        Iterator it = issueMap.entrySet().iterator();
        Issue newIssue = new Issue();
        newIssue.setName(name);

        // get all of the available fields out of the map
        while(it.hasNext()) {
            Map.Entry<String,String> pair = (Map.Entry) it.next();

            switch (pair.getKey()) {
                case "detail":
                    newIssue.setDetail(pair.getValue());
                    break;
                case "remediation":
                    newIssue.setRemediation(pair.getValue());
                    break;
                case "severity":
                    newIssue.setSeverity(pair.getValue());
                    break;
                case "regex":
                    newIssue.setRegex(pair.getValue());
                    break;
                default:
            }
        }

        return newIssue;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public String getRemediation() {
        return remediation;
    }

    public void setRemediation(String remediation) {
        this.remediation = remediation;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    public String toString() {
        return this.getName();
    }
}
